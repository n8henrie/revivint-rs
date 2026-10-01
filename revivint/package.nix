{
  lib,
  rustPlatform,
}:
let
  inherit ((lib.importTOML ./Cargo.toml).package) name description;
  inherit ((lib.importTOML ../Cargo.toml).workspace.package) version;
in
rustPlatform.buildRustPackage (finalAttrs: {
  pname = name;
  inherit version;
  src = lib.cleanSource ../.;
  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [
    "--package"
    finalAttrs.pname
  ];

  cargoTestFlags = [ "--all-features" ];

  meta = {
    inherit description;
    homepage = "https://github.com/n8henrie/revivint-rs";
    license = lib.licenses.mit;
    mainProgram = finalAttrs.pname;
  };
})
