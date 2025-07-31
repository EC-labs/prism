{ pkgs ? import <nixpkgs> {}, crate2nixTools }:
    let
      customBuildRustCrateForPkgs = pkgs: pkgs.buildRustCrate.override {
        defaultCrateOverrides = pkgs.defaultCrateOverrides // {
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
      };
      generatedCargoNix = import (
        (pkgs.callPackage crate2nixTools {}).generatedCargoNix { 
          src = ./.; 
          name = "prism";
          additionalCrateHashes = { "git+https://github.com/libbpf/vmlinux.h.git?rev=172793d6a409d98d1cfb843c80df73733e9f832f#vmlinux@0.0.0" = "0m1afca7w0fhb4szai65y09j8xf2mxzlns70k6bpngz1rsrds2cb"; };
        }
      );

    in pkgs.callPackage generatedCargoNix {
        buildRustCrateForPkgs = customBuildRustCrateForPkgs;
    }
