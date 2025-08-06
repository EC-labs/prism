{
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
        flake-utils.url = "github:numtide/flake-utils";
        crate2nix = {
            url = "github:landaudiogo/crate2nix";
            inputs.nixpkgs.follows = "nixpkgs";
        };
    };
    outputs = { self, nixpkgs, flake-utils, crate2nix }: 
        let 
            systems = [ "x86_64-linux" "aarch64-linux" ];
        in
        flake-utils.lib.eachSystem systems (system:
            let 
                pkgs = nixpkgs.legacyPackages.${system};
                crate2nixTools = crate2nix.lib.tools;
                generatedBuild = import ./default.nix { inherit pkgs crate2nixTools; };
            in rec {
                prism = generatedBuild.workspaceMembers.metric-collector.build;
                prismImage = pkgs.dockerTools.buildImage {
                    name = "prism";
                    tag = "latest";
                    copyToRoot = [ prism ];
                    config = {
                        Entrypoint = [ "/bin/metric-collector" ];
                    };
                };
                shell = with pkgs; stdenv.mkDerivation {
                    name = "prism";
                    hardeningDisable = [ "stackprotector" "zerocallusedregs" ];

                    nativeBuildInputs = [ 
                        rustfmt
                        rust-analyzer
                        rustc
                        cargo
                        elfutils
                        libz
                        pkg-config 
                        libclang.lib
                        clang
                        bpftrace
                        linuxHeaders
                        zsh
                        strace
                        netcat-openbsd
                        tcpdump
                    ];

                    buildInputs = [ 
                        duckdb
                        openssl
                        protobuf
                    ];

                    LIBCLANG_PATH = "${libclang.lib}/lib";
                };
                notebooks = pkgs.mkShell {
                    packages = [
                        (pkgs.python3.withPackages (python-pkgs: with python-pkgs; [
                          # select Python packages here
                          pandas
                          matplotlib
                          notebook
                        ]))
                    ];
                };
            }
        );
}
