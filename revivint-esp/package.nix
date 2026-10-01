{
  lib,
  rustPlatform,
  lld,
}:
let
  inherit ((lib.importTOML ./Cargo.toml).package) name description;
  inherit ((lib.importTOML ../Cargo.toml).workspace.package) version;
  target = "riscv32imc-unknown-none-elf";

  # A device without these cannot join your network or decode your sensors, so
  # the build refuses rather than flash the placeholder defaults in the source.
  required = [
    "MQTT_BROKER_IP"
    "VIVINT_KEYS"
    "WIFI_PASS"
    "WIFI_SSID"
  ];
in
rustPlatform.buildRustPackage {
  pname = name;
  inherit version;

  src = lib.cleanSource ../.;
  cargoLock.lockFile = ../Cargo.lock;

  nativeBuildInputs = [ lld ];

  env =
    lib.filterAttrs (_: v: v != "") (
      lib.genAttrs (
        required
        ++ [
          "ESP_LOG"
          "HA_DISCOVERY"
          "HA_DISCOVERY_PREFIX"
          "MQTT_BROKER_PORT"
          "MQTT_CLIENT_ID"
          "MQTT_NODE_ID"
          "MQTT_PASS"
          "MQTT_TOPIC_PREFIX"
          "MQTT_USER"
        ]
      ) builtins.getEnv
    )
    // {
      RUSTC_BOOTSTRAP = "1";
    };

  # Checked here, in the build, because the values arrive through `env` above:
  # unset ones are simply absent. A build-time check also leaves `nix flake
  # check`, which only evaluates packages, working without any settings.
  preBuild = ''
    missing=()
    for var in ${lib.escapeShellArgs required}; do
      [[ -n "''${!var-}" ]] || missing+=("$var")
    done
    if (( ''${#missing[@]} )); then
      echo "${name}: missing ''${missing[*]}" >&2
      echo "Export them and build with --impure; a pure build cannot see your" >&2
      echo "environment. See .env.sample and revivint-esp/README.md." >&2
      exit 1
    fi
  '';

  auditable = false;
  doCheck = false;
  dontFixup = true;

  buildPhase = ''
    runHook preBuild

    pushd "${name}"
    cargo build --release \
      --frozen \
      --jobs "$NIX_BUILD_CORES"
    popd

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm755 "target/${target}/release/${name}" "$out/bin/${name}"
    runHook postInstall
  '';

  # For regenerating the dev-dependency pins; see ./Cargo.toml.
  passthru = { inherit (rustPlatform) rustLibSrc; };

  meta = {
    inherit description;
    homepage = "https://github.com/n8henrie/revivint-rs";
    license = lib.licenses.mit;
    mainProgram = name;
  };
}
