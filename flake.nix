{
  description = "Decode and recover seeds for Vivint 345 MHz DW21 door sensors";

  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      # No x86_64-darwin: nixpkgs 26.11 dropped it, so its outputs no longer evaluate.
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
      ];
      eachSystem =
        with nixpkgs.lib;
        f: foldAttrs mergeAttrs { } (map (s: mapAttrs (_: v: { ${s} = v; }) (f s)) systems);
    in
    eachSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        makeApp = name: description: text: {
          type = "app";
          meta = { inherit description; };
          program = pkgs.lib.getExe (
            pkgs.writeShellApplication {
              inherit name text;
              runtimeInputs = [ pkgs.espflash ];
            }
          );
        };
      in
      {
        packages = {
          default = self.packages.${system}.revivint;
          revivint = pkgs.callPackage ./revivint/package.nix { };
          revivint-esp = pkgs.callPackage ./revivint-esp/package.nix {
            rustPlatform = pkgs.callPackage ./revivint-esp/rustplatform-with-src.nix { };
          };
        };

        apps = {
          default = self.apps.${system}.revivint;

          revivint = {
            type = "app";
            inherit (self.packages.${system}.revivint) meta;
            program = pkgs.lib.getExe self.packages.${system}.revivint;
          };

          # cp .env.sample .env
          # edit .env
          # source .env
          # nix run --impure .#flash
          flash = makeApp "revivint-flash" "Build the firmware from the environment, flash it and monitor" ''
            espflash flash --monitor "$@" \
              ${pkgs.lib.getExe self.packages.${system}.revivint-esp}
          '';
          monitor = makeApp "revivint-monitor" "Attach to the firmware's serial console" ''
            espflash monitor "$@"
          '';
        };

        devShells.default = pkgs.mkShell {
          buildInputs = (
            with pkgs;
            [
              espflash
              lld
              rust-analyzer
              rustfmt
            ]
          );
          RUSTC_BOOTSTRAP = 1;
        };
      }
    );
}
