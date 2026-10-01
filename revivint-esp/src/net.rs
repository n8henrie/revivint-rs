//! Wi-Fi + MQTT publishing: esp-radio (STA) + embassy-net (DHCP/TCP) + rust-mqtt,
//! with **Home Assistant MQTT discovery on by default**.
//!
//! Decoupled from the RF path: the decode loop calls [`report`] (a non-blocking
//! `try_send` into a channel) so network latency/reconnects never stall the
//! capture loop. A dedicated [`mqtt_task`] drains the channel and publishes.
//!
//! # What lands on the broker
//!
//! For prefix `vivint` (see `MQTT_TOPIC_PREFIX`) and sensor `0x63139`:
//!
//! ```text
//! vivint/status          "online"  (retained; "offline" is the MQTT will)
//! vivint/63139/state     {"id":"63139","event":"contact","state":"open",...}
//! vivint/63139/contact   "open" | "closed"
//! vivint/63139/battery   "ok" | "low"
//! vivint/63139/tamper    "ON" | "OFF"
//! homeassistant/binary_sensor/vivint/63139_contact/config   (retained)
//! ```
//!
//! Each sensor is announced to Home Assistant the first time it is heard on a
//! given connection: three retained `binary_sensor` configs (contact, battery,
//! tamper) grouped under one HA device. Nothing to add to `configuration.yaml`.
//! Set `HA_DISCOVERY=0` to publish only the plain topics.
//!
//! # Build-time configuration
//!
//! Everything is read from env vars at *build* time, so no secrets land in the
//! binary unless you set them:
//!
//! ```bash
//! WIFI_SSID=myssid WIFI_PASS=secret MQTT_BROKER_IP=192.168.1.10 \
//!   MQTT_TOPIC_PREFIX=vivint HA_DISCOVERY_PREFIX=homeassistant \
//!   cargo run --release
//! ```

extern crate alloc;

use embassy_executor::Spawner;
use embassy_net::tcp::TcpSocket;
use embassy_net::{
    Config as NetConfig, IpAddress, IpEndpoint, Ipv4Address, Runner, Stack, StackResources,
};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_time::{Duration, Timer};
use esp_hal::peripherals::WIFI;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::{Config as WifiConfig, Interface, WifiController};
use rust_mqtt::buffer::AllocBuffer;
use rust_mqtt::client::options::{ConnectOptions, PublicationOptions, TopicReference, WillOptions};
use rust_mqtt::client::Client;
use rust_mqtt::config::KeepAlive;
use rust_mqtt::types::{MqttBinary, MqttString, TopicName};
use rust_mqtt::Bytes;
use revivint_core::report::{self, Topics, ENTITIES};
use revivint_core::{DecodedFrame, EventKey};

// ---- deployment config (override at build time via env) ---------------------
/// `option_env!` with a default, in const context.
macro_rules! env_or {
    ($name:literal, $default:expr) => {
        match option_env!($name) {
            Some(s) => s,
            None => $default,
        }
    };
}

const WIFI_SSID: &str = env_or!("WIFI_SSID", "CHANGEME-SSID");
const WIFI_PASS: &str = env_or!("WIFI_PASS", "CHANGEME-PASS");
const BROKER_IP: &str = env_or!("MQTT_BROKER_IP", "192.168.1.10");
const BROKER_PORT: u16 = match option_env!("MQTT_BROKER_PORT") {
    Some(s) => parse_u16(s),
    None => 1883,
};
const MQTT_USER: Option<&str> = option_env!("MQTT_USER");
const MQTT_PASS: Option<&str> = option_env!("MQTT_PASS");
/// MQTT client id. Must be unique per bridge on the broker.
const CLIENT_ID: &str = env_or!("MQTT_CLIENT_ID", "vivint-345");
/// Root of every sensor topic, e.g. `vivint/63139/contact`.
const TOPIC_PREFIX: &str = env_or!("MQTT_TOPIC_PREFIX", report::DEFAULT_PREFIX);
/// Where Home Assistant listens for discovery configs.
const DISCOVERY_PREFIX: &str = env_or!("HA_DISCOVERY_PREFIX", report::DEFAULT_DISCOVERY_PREFIX);
/// Identifies *this bridge* inside discovery topics and unique ids. Keep stable:
/// changing it orphans the existing entities in Home Assistant.
const NODE_ID: &str = env_or!("MQTT_NODE_ID", report::DEFAULT_PREFIX);
/// Home Assistant discovery is on unless `HA_DISCOVERY` is set to `0`/`false`/`off`.
const HA_DISCOVERY: bool = match option_env!("HA_DISCOVERY") {
    Some(s) => !matches!(s.as_bytes(), b"0" | b"false" | b"off" | b"no"),
    None => true,
};

/// **Survey mode**: `HA_DISCOVERY=all` announces every device heard, not just
/// the ones `VIVINT_KEYS` declares.
///
/// 345 MHz is a shared band — 2GIG, Honeywell and Resideo sensors all live there
/// — so a working receiver hears the neighbourhood, not just your house. The
/// default is therefore to announce only declared devices; strangers are still
/// decoded and still published to their plain `vivint/<id>/...` topics, they
/// simply do not become Home Assistant devices.
///
/// Turn this on to find your own TXIDs during bring-up, read them off the
/// broker, put them in `VIVINT_KEYS`, then turn it off. Leaving it on is how the
/// device list fills with other people's sensors — and because discovery configs
/// are published **retained**, they outlive the build that announced them and
/// must be cleared from the broker by hand.
const HA_DISCOVERY_ALL: bool = matches!(
    option_env!("HA_DISCOVERY"),
    Some(s) if matches!(s.as_bytes(), b"all" | b"survey")
);

/// The devices `VIVINT_KEYS` declares. Discovery is limited to these unless
/// [`HA_DISCOVERY_ALL`].
static POLICY: revivint_core::Policy = revivint_core::Policy::from_map(&revivint_core::KEYS);

/// The topic layout this build publishes under.
const TOPICS: Topics<'static> = Topics {
    prefix: TOPIC_PREFIX,
    discovery_prefix: DISCOVERY_PREFIX,
    node_id: NODE_ID,
};

/// Seed for TCP ISN + MQTT packet ids. Not security-critical here.
const NET_SEED: u64 = 0x5669_7669_6e74_3435; // "Vivint45"
/// TCP-level keep-alive interval.
///
/// Deliberately **not** MQTT-level: `rust_mqtt`'s `ping()` only *sends* PINGREQ,
/// while the broker answers every one with a PINGRESP. Nothing consumed those
/// replies, so the receive buffer filled, the broker's writes blocked and it
/// dropped us — the next ping then failed on the write and we reconnected, once
/// per keep-alive period, forever.
///
/// Draining them with `poll()` in the publish loop is not the fix either:
/// `poll()` is not cancellation-safe, and a `select` that abandons it mid-packet
/// desynchronises the stream. Letting TCP do liveness removes the whole problem:
/// the MQTT session is `KeepAlive::Infinite`, no PINGREQ is ever sent, and there
/// is nothing to read back.
const TCP_KEEPALIVE_SECS: u64 = 15;

/// How long the socket may go without hearing *anything* from the broker before
/// smoltcp aborts it.
///
/// **This must stay comfortably larger than [`TCP_KEEPALIVE_SECS`].** The two
/// were previously both 30 s, and that is not a near-miss, it is a guaranteed
/// disconnect: smoltcp arms both timers off the same instant, and in `dispatch()`
/// the timeout check runs *before* the keep-alive branch. At t+30 s the socket
/// therefore aborts on the timeout without ever sending the probe that would
/// have refreshed it. Since this session never receives anything on its own —
/// QoS 0 publishes get no PUBACK and `KeepAlive::Infinite` sends no PINGREQ — a
/// quiet link died every 30 s, the will fired, and Home Assistant showed the
/// device flapping to "unavailable" between events.
///
/// At 4x the probe interval a genuinely dead link is still detected in a minute,
/// but three probes have to go unanswered first.
const TCP_TIMEOUT_SECS: u64 = TCP_KEEPALIVE_SECS * 4;

const _: () = assert!(
    TCP_TIMEOUT_SECS > TCP_KEEPALIVE_SECS,
    "the abort timeout must outlast the keep-alive probe, or the socket aborts \
     before it ever probes",
);

/// Bounded hand-off of decoded frames from the RF loop to the MQTT task.
/// Decoded frames waiting to be published.
///
/// Sized for a whole burst: the sensor repeats each event ~6 times and a capture
/// can yield several, so a depth of 8 could overflow mid-burst — and the frame
/// dropped might be the one carrying a *new* state rather than a duplicate.
/// Deduplication happens on the consumer side, so everything the radio decodes
/// has to fit here first.
static REPORTS: Channel<CriticalSectionRawMutex, DecodedFrame, 32> = Channel::new();

/// Non-blocking publish from the decode loop. Drops the frame if the queue is
/// full (network is down/slow) — the sensor re-sends, so this is fine.
pub fn report(frame: DecodedFrame) {
    let _ = REPORTS.try_send(frame);
}

/// Allocate a `'static` from a one-shot `StaticCell`.
macro_rules! mk_static {
    ($t:ty, $val:expr) => {{
        static CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        CELL.init($val)
    }};
}

/// Bring up Wi-Fi + the network stack and spawn the three background tasks.
/// The RTOS scheduler must already be started (`esp_rtos::start`) — esp-radio
/// requires it. Returns the label of the first failed step.
pub fn start(spawner: Spawner, wifi: WIFI<'static>) -> Result<(), &'static str> {
    let (controller, interfaces) =
        esp_radio::wifi::new(wifi, Default::default()).map_err(|_| "esp_radio::wifi::new")?;

    let resources = mk_static!(StackResources<4>, StackResources::new());
    let (stack, runner) = embassy_net::new(
        interfaces.station,
        NetConfig::dhcpv4(Default::default()),
        resources,
        NET_SEED,
    );

    // embassy-executor 0.9+ hands back a Result: each `#[task]` has a fixed pool
    // (one instance here), so a second spawn would be the error case.
    spawner.spawn(net_task(runner).map_err(|_| "spawn net_task")?);
    spawner.spawn(wifi_task(controller).map_err(|_| "spawn wifi_task")?);
    spawner.spawn(mqtt_task(stack).map_err(|_| "spawn mqtt_task")?);
    Ok(())
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, Interface<'static>>) -> ! {
    runner.run().await
}

/// Connect, then sit on the disconnect event and reconnect. esp-radio starts the
/// driver as part of `connect_async`, so there is no separate start step.
#[embassy_executor::task]
async fn wifi_task(mut controller: WifiController<'static>) {
    let station = StationConfig::default()
        .with_ssid(WIFI_SSID)
        // esp-radio holds the passphrase as an owned String (hence the heap).
        .with_password(WIFI_PASS.into());
    if controller
        .set_config(&WifiConfig::Station(station))
        .is_err()
    {
        log::error!("wifi: rejected SSID/password config; check WIFI_SSID / WIFI_PASS");
        return;
    }
    loop {
        match controller.connect_async().await {
            Ok(_) => {
                log::info!("wifi: connected to {WIFI_SSID}");
                let _ = controller.wait_for_disconnect_async().await;
                log::warn!("wifi: disconnected; reconnecting");
            }
            Err(e) => {
                log::warn!("wifi: connect failed ({e:?}); retrying in 5s");
                Timer::after(Duration::from_secs(5)).await;
            }
        }
    }
}

/// Sensors already announced to Home Assistant on the current connection.
/// Reset on reconnect so a broker that lost its retained set is re-populated.
type Announced = heapless::Vec<u32, 16>;

#[embassy_executor::task]
async fn mqtt_task(stack: Stack<'static>) {
    stack.wait_config_up().await;
    log::info!("net: up, v4={:?}", stack.config_v4());

    let Some(broker) = parse_ipv4(BROKER_IP).map(|ip| IpEndpoint::new(IpAddress::Ipv4(ip), BROKER_PORT))
    else {
        log::error!("net: bad MQTT_BROKER_IP {BROKER_IP:?}; mqtt disabled");
        return;
    };
    log::info!(
        "mqtt: broker {broker:?}, topics {TOPIC_PREFIX}/<id>/..., ha discovery {}",
        match (HA_DISCOVERY, HA_DISCOVERY_ALL) {
            (false, _) => "disabled",
            (true, true) => "ALL devices heard (survey mode)",
            (true, false) => "declared devices only",
        }
    );
    if HA_DISCOVERY_ALL {
        log::warn!(
            "mqtt: HA_DISCOVERY=all announces every sender on the air, including \
             neighbours'. Discovery configs are retained, so they persist on the \
             broker after you turn this off."
        );
    }

    let mut rx = [0u8; 1536];
    let mut tx = [0u8; 1536];
    loop {
        let mut socket = TcpSocket::new(stack, &mut rx, &mut tx);
        socket.set_timeout(Some(Duration::from_secs(TCP_TIMEOUT_SECS)));
        // TCP keep-alive replaces the MQTT ping entirely: it probes the link
        // without generating an application-layer response we would then have to
        // read. A dead link surfaces as a socket error on the next publish.
        socket.set_keep_alive(Some(Duration::from_secs(TCP_KEEPALIVE_SECS)));
        if socket.connect(broker).await.is_err() {
            log::warn!("mqtt: tcp connect to {broker:?} failed; retrying");
            Timer::after(Duration::from_secs(5)).await;
            continue;
        }
        if let Err(step) = session(socket).await {
            log::warn!("mqtt: {step}; reconnecting");
        }
        Timer::after(Duration::from_secs(5)).await;
    }
}

/// One broker session: connect, announce availability, then publish frames until
/// something fails. Returns the label of the step that ended the session.
async fn session(socket: TcpSocket<'_>) -> Result<(), &'static str> {
    let mut avail_buf = [0u8; 96];
    let availability = TOPICS
        .availability(&mut avail_buf)
        .ok_or("availability topic too long for its buffer")?;
    let will_topic = topic_name(availability).ok_or("availability topic is not a valid MQTT topic")?;

    let mut buffer = AllocBuffer;
    // <MAX_SUBSCRIBES, RECEIVE_MAXIMUM, SEND_MAXIMUM, MAX_SUBSCRIPTION_IDENTIFIERS>
    // We only ever publish at QoS 0, so one of each is plenty.
    let mut client = Client::<'_, _, _, 1, 1, 1, 1>::new(&mut buffer);

    let mut opts = ConnectOptions::new()
        .clean_start()
        // See TCP_KEEPALIVE_SECS: liveness is handled at the TCP layer so the
        // session never needs a PINGREQ (and so never gets a PINGRESP to read).
        .keep_alive(KeepAlive::Infinite)
        // Tell the broker to flip us to "offline" if this link dies, so Home
        // Assistant marks the entities unavailable instead of showing stale state.
        .will(
            WillOptions::new(
                will_topic.clone(),
                MqttBinary::try_from(b"offline".as_slice()).map_err(|_| "will payload")?,
            )
            .retain(),
        );
    if let Some(u) = MQTT_USER {
        opts = opts.user_name(MqttString::try_from(u).map_err(|_| "MQTT_USER is not valid UTF-8")?);
    }
    if let Some(p) = MQTT_PASS {
        opts = opts.password(MqttBinary::try_from(p.as_bytes()).map_err(|_| "MQTT_PASS too long")?);
    }
    let client_id = MqttString::try_from(CLIENT_ID).map_err(|_| "MQTT_CLIENT_ID invalid")?;

    client
        .connect(socket, &opts, Some(client_id))
        .await
        .map_err(|_| "broker connect failed")?;
    log::info!("mqtt: connected as {CLIENT_ID}");

    publish(&mut client, availability, b"online", true).await?;

    let mut announced = Announced::new();
    let mut last_seen = LastSeen::new();
    // Just publish. Liveness is TCP's job (see TCP_KEEPALIVE_SECS), so there is
    // no ping to send and no response to drain — which keeps this loop free of
    // any future that must not be cancelled.
    loop {
        let frame = REPORTS.receive().await;
        if is_repeat(&mut last_seen, &frame) {
            continue;
        }
        publish_frame(&mut client, &frame, &mut announced).await?;
    }
}

/// The last event published per device, so a repeat is not published twice.
///
/// The sensor sends each event ~6 times, and a capture can also yield the same
/// frame from more than one Manchester run — so one physical reed change arrived
/// as a dozen identical publishes. The radio should still *decode* all of them
/// (more chances at a clean one); only the publish is collapsed.
///
/// Identity comes from [`DecodedFrame::event_key`], which includes the status
/// byte. An earlier version keyed on `(txid, type, counter)` and silently
/// dropped every second state change, because one counter is transmitted in
/// both contact states — MQTT then republished the same value indefinitely.
///
/// That bug survived a fix to `event_key` because this table stored a bare
/// tuple and compared it field by field, so the new field simply was not looked
/// at. It holds whole [`EventKey`] values now and compares them with `==`: a
/// field added to the key is compared here with no edit to this file.
type LastSeen = heapless::Vec<EventKey, 16>;

/// True if this frame is a repeat of the last event published for its device.
fn is_repeat(last: &mut LastSeen, f: &DecodedFrame) -> bool {
    if f.counter().is_none() {
        // No counter (legacy, startup) means no event identity to compare;
        // always publish.
        return false;
    }
    let key = f.event_key();
    for seen in last.iter_mut() {
        if seen.same_device(key) {
            if *seen == key {
                return true;
            }
            *seen = key;
            return false;
        }
    }
    let _ = last.push(key);
    false
}

/// Publish everything one decoded frame has to say.
async fn publish_frame<N, B>(
    client: &mut Client<'_, N, B, 1, 1, 1, 1>,
    frame: &DecodedFrame,
    announced: &mut Announced,
) -> Result<(), &'static str>
where
    N: rust_mqtt::io::Transport,
    B: for<'b> rust_mqtt::buffer::BufferProvider<'b>,
{
    // Announce only what the operator declared. A stranger's frames still reach
    // their plain topics below; they just do not create an HA device.
    if HA_DISCOVERY
        && (HA_DISCOVERY_ALL || POLICY.declares(frame.txid))
        && !announced.contains(&frame.txid)
    {
        announce(client, frame.txid).await?;
        // If the table is full we simply re-announce next time: harmless, and it
        // keeps a large install from silently dropping later sensors.
        let _ = announced.push(frame.txid);
    }

    // Full detail as JSON, also attached to every entity as its attributes.
    let mut topic_buf = [0u8; 96];
    let mut payload_buf = [0u8; 224];
    if let (Some(topic), Some(body)) = (
        TOPICS.state(&mut topic_buf, frame.txid),
        report::payload(&mut payload_buf, frame),
    ) {
        publish(client, topic, body.as_bytes(), false).await?;
    } else {
        log::warn!("mqtt: state topic/payload did not fit; skipping");
    }

    // One leaf per entity, published only when this frame actually carries that
    // value — a heartbeat says nothing about the door, so it must not overwrite it.
    for &e in &ENTITIES {
        let Some(value) = e.value(frame) else { continue };
        let mut buf = [0u8; 96];
        let Some(topic) = TOPICS.leaf(&mut buf, frame.txid, e.leaf()) else {
            continue;
        };
        publish(client, topic, value.as_bytes(), false).await?;
    }
    Ok(())
}

/// Publish the retained Home Assistant discovery configs for one sensor.
async fn announce<N, B>(
    client: &mut Client<'_, N, B, 1, 1, 1, 1>,
    txid: u32,
) -> Result<(), &'static str>
where
    N: rust_mqtt::io::Transport,
    B: for<'b> rust_mqtt::buffer::BufferProvider<'b>,
{
    log::info!("mqtt: announcing sensor {txid:05x} to home assistant");
    for &e in &ENTITIES {
        let (mut sb, mut eb, mut ab) = ([0u8; 96], [0u8; 96], [0u8; 96]);
        let (Some(state), Some(entity), Some(avail)) = (
            TOPICS.state(&mut sb, txid),
            TOPICS.leaf(&mut eb, txid, e.leaf()),
            TOPICS.availability(&mut ab),
        ) else {
            log::warn!("mqtt: topics too long for discovery; shorten MQTT_TOPIC_PREFIX");
            return Ok(());
        };
        let mut cfg_topic_buf = [0u8; 160];
        let mut cfg_buf = [0u8; 512];
        let (Some(cfg_topic), Some(cfg)) = (
            TOPICS.discovery(&mut cfg_topic_buf, txid, e),
            report::discovery_payload(&mut cfg_buf, &TOPICS, txid, e, state, entity, avail),
        ) else {
            log::warn!("mqtt: discovery config for {e:?} did not fit; skipping");
            continue;
        };
        publish(client, cfg_topic, cfg.as_bytes(), true).await?;
    }
    Ok(())
}

/// QoS-0 publish. `retain` is what makes availability and discovery survive a
/// Home Assistant restart.
async fn publish<N, B>(
    client: &mut Client<'_, N, B, 1, 1, 1, 1>,
    topic: &str,
    payload: &[u8],
    retain: bool,
) -> Result<(), &'static str>
where
    N: rust_mqtt::io::Transport,
    B: for<'b> rust_mqtt::buffer::BufferProvider<'b>,
{
    let name = topic_name(topic).ok_or("invalid MQTT topic")?;
    let mut opts = PublicationOptions::new(TopicReference::Name(name));
    if retain {
        opts = opts.retain();
    }
    client
        .publish(&opts, Bytes::from(payload))
        .await
        .map(|_| ())
        .map_err(|_| "publish failed")
}

fn topic_name(s: &str) -> Option<TopicName<'_>> {
    TopicName::new(MqttString::try_from(s).ok()?)
}

// ---- tiny const/runtime parse helpers (no_std, no deps) ---------------------

/// Parse a `u16` in a const context (build-time port). 0 on malformed input.
const fn parse_u16(s: &str) -> u16 {
    let b = s.as_bytes();
    let mut i = 0;
    let mut v: u16 = 0;
    while i < b.len() {
        let d = b[i];
        if d < b'0' || d > b'9' {
            return 0;
        }
        v = v * 10 + (d - b'0') as u16;
        i += 1;
    }
    v
}

/// Parse a dotted-quad IPv4 at runtime.
fn parse_ipv4(s: &str) -> Option<Ipv4Address> {
    let mut octets = [0u8; 4];
    let mut idx = 0;
    for part in s.split('.') {
        if idx >= 4 {
            return None;
        }
        octets[idx] = part.parse::<u8>().ok()?;
        idx += 1;
    }
    (idx == 4).then(|| Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]))
}
