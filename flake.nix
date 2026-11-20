{
  # The PKCS#11 provider as a Nix package, for Flox and Nix (docs/milestone-7.md, Distribution):
  #   flox install github:<owner>/pkcs11-relay/<tag>#relay-pkcs11   → $FLOX_ENV/lib/librelay_pkcs11.{dylib,so}
  #   nix build .#relay-pkcs11                                       → result/lib/…
  # Built from source with the rustc in the pinned nixpkgs. mise's Rust follows that version
  # (`mise run sync-rust`); `nix flake check` fails if mise.toml pins a different one.
  description = "relay-pkcs11: approval-gated PKCS#11 provider";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAll = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      workspace = (lib.importTOML ./Cargo.toml).workspace.package;
      miseRust = (lib.importTOML ./mise.toml).tools.rust.version;
    in
    {
      packages = forAll (pkgs: rec {
        default = relay-pkcs11;
        relay-pkcs11 = pkgs.rustPlatform.buildRustPackage {
          pname = "relay-pkcs11";
          inherit (workspace) version;
          # Only what cargo needs, so docs or app changes don't rebuild the package.
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./crates
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "-p"
            "relay-pkcs11"
          ];
          # The provider's tests run under mise in CI with the same rustc (versions synced);
          # here they would also build the relay and test approver for every install.
          doCheck = false;
          # On macOS this builds for nixpkgs' deployment target (14.0), which nixpkgs itself
          # requires; darwinMinVersionHook can only raise it. The release-asset dylib from
          # deploy/macos/build-provider.sh targets 13.0 for people without Nix.
          installPhase = ''
            runHook preInstall
            lib=$(find target -path '*/release/librelay_pkcs11${pkgs.stdenv.hostPlatform.extensions.sharedLibrary}' | head -n1)
            install -Dm644 "$lib" "$out/lib/$(basename "$lib")"
          ''
          + lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
            # Callers dlopen the module by path; @rpath only matters for tools that link it.
            # The fixup phase re-signs it (ad hoc) after this change.
            install_name_tool -id "@rpath/$(basename "$lib")" "$out/lib/$(basename "$lib")"
          ''
          + ''
            runHook postInstall
          '';
          meta = {
            description = "Approval-gated PKCS#11 provider: forwards each sign or decrypt to an approver app";
            license = lib.licenses.asl20;
            platforms = systems;
          };
        };
      });

      checks = forAll (pkgs: {
        relay-pkcs11 = self.packages.${pkgs.stdenv.hostPlatform.system}.relay-pkcs11;
        rust-version-in-sync =
          if pkgs.rustc.version == miseRust then
            pkgs.runCommand "rust-version-in-sync" { } "touch $out"
          else
            throw "mise.toml pins Rust ${miseRust}, but the flake's nixpkgs has ${pkgs.rustc.version}: run `mise run sync-rust`";
      });
    };
}
