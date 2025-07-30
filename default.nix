{ pkgs ? import <nixpkgs> {} }:
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
    in pkgs.callPackage ./Cargo.nix {
        buildRustCrateForPkgs = customBuildRustCrateForPkgs;
    }
