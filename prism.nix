{pkgs, lib}: 
    pkgs.rustPlatform.buildRustPackage {
        pname = "prism";
        version = "0.0.1";

        hardeningDisable = [ "stackprotector" "zerocallusedregs" ];
        doCheck = false;

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

        src = builtins.filterSource 
          (path: type: !(type == "directory" && (baseNameOf path == "target" || baseNameOf path == "data")))
          ./.;

        cargoBuildFlags = [ "--package" "metric-collector" ];

        cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes = {
                "vmlinux-0.0.0" = "sha256-iwndss7hP3uXmeBoS3+vwnUkE/DFRPU1WdABfhRzKlQ=";
            };
        };
    }
