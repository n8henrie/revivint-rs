//! MQTT topic + payload formatting into caller-provided byte buffers (no alloc).
//!
//! Two things live here:
//!
//! * **Topics** ([`Topics`]) — every topic is built from a runtime `prefix`, so a
//!   deployment can namespace its sensors (`MQTT_TOPIC_PREFIX`) without a rebuild.
//! * **Home Assistant MQTT discovery** ([`Topics::discovery`] / [`discovery_payload`])
//!   — retained config messages that make each sensor appear in HA by itself, no
//!   YAML. See [`ENTITIES`].
//!
//! Layout, for prefix `vivint` and sensor `0x63139`:
//!
//! ```text
//! vivint/status            "online" / "offline"   (retained; MQTT will topic)
//! vivint/63139/state       {"id":"63139","event":"contact",...}   (full JSON)
//! vivint/63139/contact     "open" / "closed"
//! vivint/63139/battery     "ok" / "low"
//! vivint/63139/tamper      "ON" / "OFF"
//! homeassistant/binary_sensor/vivint/63139_contact/config   (retained discovery)
//! ```
//!
//! Each entity gets its **own** leaf topic rather than a template over the JSON:
//! a heartbeat frame carries no contact state, and an HA `value_template` reading
//! a missing field would log errors and flap the entity. Publishing a leaf only
//! when the frame actually carries that value keeps entities stable, and the JSON
//! `state` topic is attached as `json_attributes_topic` for the full detail.

use crate::frame::{Body, DecodedFrame};
use core::fmt::Write;

/// A `core::fmt::Write` sink over a fixed byte buffer.
///
/// Writing past the end truncates rather than panicking, but sets
/// [`overflowed`](FixedWriter::overflowed) — callers that emit JSON must check it,
/// since a truncated payload is malformed rather than merely short.
pub struct FixedWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overflowed: bool,
}

impl<'a> FixedWriter<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0, overflowed: false }
    }

    pub fn as_str(&self) -> &str {
        // Only ASCII is ever written here, so this is always valid UTF-8.
        core::str::from_utf8(&self.buf[..self.pos]).unwrap_or("")
    }

    /// True if any write did not fit. The buffer holds a prefix of the intended
    /// output, which is fine for a log line and *not* fine for JSON.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }

    /// The written slice, or `None` if it was truncated.
    fn finish(self) -> Option<usize> {
        (!self.overflowed).then_some(self.pos)
    }
}

impl Write for FixedWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let n = bytes.len().min(self.buf.len() - self.pos);
        self.buf[self.pos..self.pos + n].copy_from_slice(&bytes[..n]);
        self.pos += n;
        if n == bytes.len() {
            Ok(())
        } else {
            self.overflowed = true;
            Err(core::fmt::Error)
        }
    }
}

/// Run `f` against a writer over `buf` and return the written `&str`, or `None`
/// if it did not fit.
fn build<F>(buf: &mut [u8], f: F) -> Option<&str>
where
    F: FnOnce(&mut FixedWriter<'_>),
{
    let n = {
        let mut w = FixedWriter::new(buf);
        f(&mut w);
        w.finish()?
    };
    core::str::from_utf8(&buf[..n]).ok()
}

// ---- topics -----------------------------------------------------------------

/// Default topic prefix; override per deployment (firmware reads
/// `MQTT_TOPIC_PREFIX`).
pub const DEFAULT_PREFIX: &str = "vivint";
/// Default Home Assistant discovery prefix (HA's own default; override with
/// `HA_DISCOVERY_PREFIX`).
pub const DEFAULT_DISCOVERY_PREFIX: &str = "homeassistant";

/// The topic namespace for one deployment. Cheap to copy; hold one in the MQTT
/// task and build topics from it as frames arrive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Topics<'a> {
    /// Topic root for sensor data, e.g. `vivint`.
    pub prefix: &'a str,
    /// Home Assistant discovery root, e.g. `homeassistant`.
    pub discovery_prefix: &'a str,
    /// Node id identifying *this bridge* inside discovery topics and unique ids,
    /// e.g. `vivint`. Keep it stable — changing it orphans HA entities.
    pub node_id: &'a str,
}

impl Default for Topics<'_> {
    fn default() -> Self {
        Topics {
            prefix: DEFAULT_PREFIX,
            discovery_prefix: DEFAULT_DISCOVERY_PREFIX,
            node_id: DEFAULT_PREFIX,
        }
    }
}

impl Topics<'_> {
    /// `<prefix>/status` — the bridge's availability topic. Publish `online`
    /// retained on connect and register `offline` as the MQTT will.
    pub fn availability<'b>(&self, buf: &'b mut [u8]) -> Option<&'b str> {
        let prefix = self.prefix;
        build(buf, |w| {
            let _ = write!(w, "{prefix}/status");
        })
    }

    /// `<prefix>/<txid>/state` — the full-detail JSON topic.
    pub fn state<'b>(&self, buf: &'b mut [u8], txid: u32) -> Option<&'b str> {
        self.leaf(buf, txid, "state")
    }

    /// `<prefix>/<txid>/<leaf>` — one entity's own topic (see [`Entity::leaf`]).
    pub fn leaf<'b>(&self, buf: &'b mut [u8], txid: u32, leaf: &str) -> Option<&'b str> {
        let prefix = self.prefix;
        build(buf, |w| {
            let _ = write!(w, "{prefix}/{txid:05x}/{leaf}");
        })
    }

    /// `<discovery_prefix>/binary_sensor/<node_id>/<txid>_<leaf>/config` — where
    /// Home Assistant looks for this entity's retained config message.
    pub fn discovery<'b>(&self, buf: &'b mut [u8], txid: u32, e: Entity) -> Option<&'b str> {
        let (disc, node, leaf) = (self.discovery_prefix, self.node_id, e.leaf());
        build(buf, |w| {
            let _ = write!(w, "{disc}/binary_sensor/{node}/{txid:05x}_{leaf}/config");
        })
    }
}

// ---- entities ---------------------------------------------------------------

/// One Home Assistant `binary_sensor` derived from a decoded frame.
///
/// All three are `binary_sensor`s because that is what these frames actually
/// carry — a reed switch, a battery-low flag and a tamper flag. Counter/RSSI-style
/// numbers stay in the JSON `state` topic as attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entity {
    /// The reed switch: HA device class `door`.
    Contact,
    /// Battery low flag: HA device class `battery` (ON = low, per HA convention).
    Battery,
    /// Tamper / case-open flag: HA device class `tamper`.
    Tamper,
}

/// Every entity a sensor can publish, in discovery order.
pub const ENTITIES: [Entity; 3] = [Entity::Contact, Entity::Battery, Entity::Tamper];

impl Entity {
    /// Last path segment of this entity's topic, e.g. `contact`.
    pub fn leaf(self) -> &'static str {
        match self {
            Entity::Contact => "contact",
            Entity::Battery => "battery",
            Entity::Tamper => "tamper",
        }
    }

    /// Entity name shown under the device in Home Assistant.
    pub fn name(self) -> &'static str {
        match self {
            Entity::Contact => "Contact",
            Entity::Battery => "Battery",
            Entity::Tamper => "Tamper",
        }
    }

    /// Home Assistant `device_class`.
    pub fn device_class(self) -> &'static str {
        match self {
            Entity::Contact => "door",
            Entity::Battery => "battery",
            Entity::Tamper => "tamper",
        }
    }

    /// The payload meaning "on"/problem for this entity.
    pub fn payload_on(self) -> &'static str {
        match self {
            Entity::Contact => "open",
            Entity::Battery => "low",
            Entity::Tamper => "ON",
        }
    }

    /// The payload meaning "off"/normal for this entity.
    pub fn payload_off(self) -> &'static str {
        match self {
            Entity::Contact => "closed",
            Entity::Battery => "ok",
            Entity::Tamper => "OFF",
        }
    }

    /// This entity's value in `f`, or `None` when the frame does not carry it —
    /// a heartbeat has no contact state, a `0x7x` event has no battery reading.
    /// Publish only what a frame actually says, so entities never flap.
    pub fn value(self, f: &DecodedFrame) -> Option<&'static str> {
        let on = |b: bool| if b { self.payload_on() } else { self.payload_off() };
        match self {
            // Home Assistant's `door` class defines ON as open, so this maps
            // Contact::Open -> on. Spelled out rather than relying on a bool's
            // polarity, because an inversion here is invisible to any test that
            // only checks that the value changed.
            Entity::Contact => f.contact().map(|c| on(c.is_open())),
            // HA's battery class is inverted: ON means there is a problem.
            Entity::Battery => f.battery().map(|b| on(!b.is_ok())),
            Entity::Tamper => f.status_bits().map(|b| on(b.tamper)),
        }
    }
}

// ---- payloads ---------------------------------------------------------------

/// Compact JSON describing the frame, for the `state` topic (and attached to
/// every entity as `json_attributes_topic`). `None` if `buf` is too small —
/// 192 bytes is comfortable.
pub fn payload<'b>(buf: &'b mut [u8], f: &DecodedFrame) -> Option<&'b str> {
    build(buf, |w| {
        let _ = write!(
            w,
            "{{\"id\":\"{:05x}\",\"event\":\"{}\",\"type\":\"{:02x}\"",
            f.txid,
            f.event(),
            f.type_byte()
        );
        if let Some(c) = f.contact() {
            let _ = write!(w, ",\"state\":\"{c}\"");
        }
        if let Some(c) = f.counter() {
            let _ = write!(w, ",\"counter\":{c}");
        }
        if let Some(s) = f.status_byte() {
            let _ = write!(w, ",\"status\":{s}");
        }
        if let Some(b) = f.battery() {
            let _ = write!(w, ",\"battery_ok\":{},\"battery\":\"{b}\"", b.is_ok());
        }
        if let Body::Startup(st) = f.body {
            let _ = write!(w, ",\"battery_level\":{}", st.gauge);
        }
        if let Some(bits) = f.status_bits() {
            let _ = write!(w, ",\"tamper\":{},\"alarm\":{}", bits.tamper, bits.alarm);
        }
        let _ = write!(w, ",\"crc_ok\":{}}}", f.crc_ok);
    })
}

/// Retained Home Assistant discovery config for one entity of one sensor.
///
/// Uses HA's abbreviated keys to stay inside a small MQTT packet. The sensor is
/// declared as a *device* (`dev`) so all three entities group under one card,
/// named for the decimal id printed on the sensor (`0x63139` → `Vivint 405817`).
/// `None` if `buf` is too small — allow 512 bytes.
pub fn discovery_payload<'b>(
    buf: &'b mut [u8],
    topics: &Topics<'_>,
    txid: u32,
    e: Entity,
    state_topic: &str,
    entity_topic: &str,
    availability_topic: &str,
) -> Option<&'b str> {
    let node = topics.node_id;
    build(buf, |w| {
        let _ = write!(
            w,
            "{{\"name\":\"{}\",\"uniq_id\":\"{}_{:05x}_{}\",\"stat_t\":\"{}\"",
            e.name(),
            node,
            txid,
            e.leaf(),
            entity_topic
        );
        let _ = write!(
            w,
            ",\"json_attr_t\":\"{state_topic}\",\"avty_t\":\"{availability_topic}\""
        );
        let _ = write!(
            w,
            ",\"pl_on\":\"{}\",\"pl_off\":\"{}\",\"dev_cla\":\"{}\"",
            e.payload_on(),
            e.payload_off(),
            e.device_class()
        );
        // One device per sensor, so HA groups the three entities together.
        let _ = write!(
            w,
            ",\"dev\":{{\"ids\":[\"{node}_{txid:05x}\"],\"name\":\"Vivint {txid}\",\
             \"mf\":\"Vivint\",\"mdl\":\"345 MHz sensor\"}}}}"
        );
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::decode;

    fn hx(s: &str) -> [u8; 12] {
        let mut out = [0u8; 12];
        let b = s.as_bytes();
        for i in 0..(s.len() / 2) {
            let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }

    #[test]
    fn default_topics_match_the_documented_layout() {
        let t = Topics::default();
        let mut b = [0u8; 64];
        assert_eq!(t.state(&mut b, 0x63139).unwrap(), "vivint/63139/state");
        let mut b = [0u8; 64];
        assert_eq!(t.leaf(&mut b, 0x63139, "contact").unwrap(), "vivint/63139/contact");
        let mut b = [0u8; 64];
        assert_eq!(t.availability(&mut b).unwrap(), "vivint/status");
    }

    #[test]
    fn prefix_is_configurable_end_to_end() {
        // A deployment can namespace every topic without touching the code.
        let t = Topics { prefix: "house/rf", discovery_prefix: "ha", node_id: "bridge1" };
        let mut b = [0u8; 96];
        assert_eq!(t.state(&mut b, 0x630d6).unwrap(), "house/rf/630d6/state");
        let mut b = [0u8; 96];
        assert_eq!(
            t.discovery(&mut b, 0x630d6, Entity::Contact).unwrap(),
            "ha/binary_sensor/bridge1/630d6_contact/config"
        );
    }

    #[test]
    fn discovery_topic_is_per_entity() {
        let t = Topics::default();
        for (e, want) in [
            (Entity::Contact, "homeassistant/binary_sensor/vivint/63139_contact/config"),
            (Entity::Battery, "homeassistant/binary_sensor/vivint/63139_battery/config"),
            (Entity::Tamper, "homeassistant/binary_sensor/vivint/63139_tamper/config"),
        ] {
            let mut b = [0u8; 96];
            assert_eq!(t.discovery(&mut b, 0x63139, e).unwrap(), want);
        }
    }

    #[test]
    fn entity_values_only_appear_when_the_frame_carries_them() {
        // A bare 0x7a contact event carries no *readable* state: its byte 5 is
        // still keystreamed, so nothing may be published for it. Un-keying it
        // with the device's seed is what produces a contact value — see
        // `keyed_contact_publishes_once_un_keyed` below.
        let contact = decode(&hx("fffe7a0019d803863139a8f8")).unwrap();
        assert_eq!(Entity::Contact.value(&contact), None);
        assert_eq!(Entity::Battery.value(&contact), None);
        assert_eq!(Entity::Tamper.value(&contact), None);

        // 0xd0 startup beacon: battery only, no contact state.
        let startup = decode(&hx("fffed03a0f4003863139d6d0")).unwrap();
        assert_eq!(Entity::Contact.value(&startup), None);
        assert_eq!(Entity::Battery.value(&startup), Some("low"));

        let healthy = decode(&hx("fffed0f30f300386313978b0")).unwrap();
        assert_eq!(Entity::Battery.value(&healthy), Some("ok"));

        // 0x72 heartbeat carries none of them — nothing gets published, so the
        // HA entities keep their last real value instead of flapping.
        let hb = decode(&hx("fffe7239ab02038631394bdd")).unwrap();
        assert!(ENTITIES.iter().all(|&e| e.value(&hb).is_none()));
    }

    #[test]
    fn legacy_frame_drives_all_three_entities() {
        // A 64-bit 5718-style frame has contact, battery and tamper in the clear.
        let f = decode(&hx("fffea630d6801f10")[..8]).unwrap();
        assert_eq!(Entity::Contact.value(&f), Some("open"));
        assert_eq!(Entity::Battery.value(&f), Some("ok"));
        assert_eq!(Entity::Tamper.value(&f), Some("OFF"));
    }

    #[test]
    fn battery_entity_is_inverted_for_home_assistant() {
        // HA's `battery` device class means ON = low battery, so a healthy
        // reading must publish the *off* payload.
        let flat = decode(&hx("fffed0a50f5003863139aef0")).unwrap();
        assert_eq!(flat.battery(), Some(crate::Battery::Critical));
        assert_eq!(Entity::Battery.value(&flat), Some(Entity::Battery.payload_on()));

        let healthy = decode(&hx("fffed0f30f300386313978b0")).unwrap();
        assert_eq!(healthy.battery(), Some(crate::Battery::Ok));
        assert_eq!(Entity::Battery.value(&healthy), Some(Entity::Battery.payload_off()));
    }

    #[test]
    fn payload_contact() {
        let f = decode(&hx("fffe7a0019d803863139a8f8")).unwrap();
        let mut b = [0u8; 192];
        // Sealed: no "state", no "tamper"/"alarm" — the JSON says only what the
        // frame actually established.
        assert_eq!(
            payload(&mut b, &f).unwrap(),
            "{\"id\":\"63139\",\"event\":\"contact\",\"type\":\"7a\",\"counter\":25,\"status\":216,\"crc_ok\":true}"
        );

        // Once un-keyed with the device seed, the same frame gains its state.
        let mut d = crate::Decoder::new(0x0c5e);
        let mut keyed = f;
        crate::apply_key(&mut d, &mut keyed);
        let mut b2 = [0u8; 192];
        let json = payload(&mut b2, &keyed).unwrap();
        assert!(json.contains("\"state\":\"open\""), "{json}");
    }

    #[test]
    fn payload_startup_has_no_state() {
        let f = decode(&hx("fffed03a0f4003863139d6d0")).unwrap();
        let mut b = [0u8; 192];
        let s = payload(&mut b, &f).unwrap();
        assert!(s.contains("\"event\":\"startup\""));
        assert!(!s.contains("\"state\""));
    }

    #[test]
    fn discovery_payload_is_valid_json_and_wires_the_topics_together() {
        let t = Topics::default();
        let (mut sb, mut eb, mut ab) = ([0u8; 64], [0u8; 64], [0u8; 64]);
        let state = t.state(&mut sb, 0x63139).unwrap();
        let entity = t.leaf(&mut eb, 0x63139, Entity::Contact.leaf()).unwrap();
        let avail = t.availability(&mut ab).unwrap();

        let mut b = [0u8; 512];
        let s = discovery_payload(&mut b, &t, 0x63139, Entity::Contact, state, entity, avail)
            .expect("512 bytes is enough for a discovery config");

        assert!(s.starts_with('{') && s.ends_with('}'));
        assert_eq!(s.bytes().filter(|&c| c == b'{').count(), s.bytes().filter(|&c| c == b'}').count());
        assert!(s.contains("\"stat_t\":\"vivint/63139/contact\""));
        assert!(s.contains("\"json_attr_t\":\"vivint/63139/state\""));
        assert!(s.contains("\"avty_t\":\"vivint/status\""));
        assert!(s.contains("\"dev_cla\":\"door\""));
        assert!(s.contains("\"pl_on\":\"open\""));
        assert!(s.contains("\"uniq_id\":\"vivint_63139_contact\""));
        // Device name uses the decimal id printed on the sensor (0x63139 = 405817).
        assert!(s.contains("\"name\":\"Vivint 405817\""), "{s}");
    }

    #[test]
    fn every_entity_discovery_fits_in_512_bytes() {
        let t = Topics::default();
        for &e in &ENTITIES {
            let (mut sb, mut eb, mut ab) = ([0u8; 64], [0u8; 64], [0u8; 64]);
            let state = t.state(&mut sb, 0x63139).unwrap();
            let entity = t.leaf(&mut eb, 0x63139, e.leaf()).unwrap();
            let avail = t.availability(&mut ab).unwrap();
            let mut b = [0u8; 512];
            assert!(
                discovery_payload(&mut b, &t, 0x63139, e, state, entity, avail).is_some(),
                "{e:?} discovery must fit"
            );
        }
    }

    #[test]
    fn truncation_is_reported_not_silently_emitted() {
        // A short buffer must yield None rather than a half-written, invalid
        // JSON document that a broker would happily forward to Home Assistant.
        let f = decode(&hx("fffe7a0019d803863139a8f8")).unwrap();
        let mut b = [0u8; 16];
        assert!(payload(&mut b, &f).is_none());

        let t = Topics::default();
        let mut b = [0u8; 8];
        assert!(t.state(&mut b, 0x63139).is_none());
    }

    #[test]
    fn fixed_writer_truncates_without_panic_and_flags_it() {
        let mut b = [0u8; 8];
        let mut w = FixedWriter::new(&mut b);
        let _ = write!(w, "way too long for eight bytes");
        assert_eq!(w.as_str().len(), 8);
        assert!(w.overflowed());
    }
}
