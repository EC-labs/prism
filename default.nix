{ pkgs ? import <nixpkgs> {}, crate2nixTools }:
    let
      crateOverrides = {
          libbpf-sys = attrs: {
            buildInputs = with pkgs; [
                pkg-config
                libz
                elfutils
            ];
          };

          containerd-client = attrs: {
            buildInputs = with pkgs; [
                protobuf
            ];
          };

          metric-collector = attrs: {
            nativeBuildInputs = with pkgs; [
                rustfmt
                rust-analyzer
                rustc
                cargo
                pkg-config
                libclang.lib
                clang
                protobuf
            ];

            buildInputs = with pkgs; [
                duckdb
                openssl
                libz
                elfutils
                rdkafka
            ];

            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
            hardeningDisable = [ "stackprotector" "zerocallusedregs" ];

          };
          vmlinux = attrs: {
            postPatch = ''
                substituteInPlace \
                  src/lib.rs \
                  --replace-fail \
                  'env!("CARGO_MANIFEST_DIR")' \
                  \"$src\"
            '';
          };
      };

      customBuildRustCrateForPkgs = pkgs: pkgs.buildRustCrate.override {
        defaultCrateOverrides = pkgs.defaultCrateOverrides // crateOverrides;
      };

      generatedCargoNix = import (
        (pkgs.callPackage crate2nixTools {}).generatedCargoNix {
          src = ./.;
          name = "prism";
        }
      );

    in pkgs.callPackage generatedCargoNix {
        buildRustCrateForPkgs = customBuildRustCrateForPkgs;
    }
