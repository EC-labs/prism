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
            in {
                packages = {
                    prism = generatedBuild.workspaceMembers.metric-collector.build;
                    default = self.packages.${system}.prism;
                    ripple = self.packages.${system}.prism;
                };

                images = {
                    prism = pkgs.dockerTools.buildImage {
                        name = "dclandau/prism";
                        tag = "latest";
                        copyToRoot = [ self.packages.${system}.prism ];
                        config = {
                            Entrypoint = [ "/bin/metric-collector" ];
                        };
                    };
                    ripple = pkgs.dockerTools.buildImage {
                        name = "dclandau/ripple";
                        tag = "latest";
                        copyToRoot = [ self.packages.${system}.ripple ];
                        config = {
                            Entrypoint = [ "/bin/metric-collector" ];
                        };
                    };
                };

                devShells = {
                    default = with pkgs; mkShell {
                        name = "prism";
                        hardeningDisable = [ "stackprotector" "zerocallusedregs" ];

                        nativeBuildInputs = [ 
                            clippy
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
                    scripts = pkgs.mkShell {
                        packages = with pkgs; [
                            bpftrace
                            linuxHeaders
                            duckdb
                        ] ++ [
                            (pkgs.python3.withPackages (python-pkgs: with python-pkgs; [ ]))
                        ];
                    };
                    notebooks = pkgs.mkShell {
                        packages = [
                            (pkgs.python3.withPackages (python-pkgs: with python-pkgs; [
                              # select Python packages here
                              pandas
                              matplotlib
                              notebook
                              duckdb
                            ]))
                        ];
                    };
                    graph = pkgs.mkShell {
                        packages = with pkgs; [
                            (python3.withPackages (python-pkgs: with python-pkgs; [
                                # select Python packages here
                                graphviz
                                pyvis
                                duckdb
                                plotly 
                                networkx 
                                pandas
                            ]))
                        ] ++ [ duckdb ];
                    };
                };

                apps = {
                    prism = {
                        type = "app";
                        program = "${self.packages.${system}.prism}/bin/metric-collector";
                    };
                    ripple = {
                        type = "app";
                        program = "${self.packages.${system}.ripple}/bin/metric-collector";
                    };
                    pushImages = 
                        let
                            loadPush = imageDerivation: ''
                                image=$(docker load < ${imageDerivation} | sed -nE 's/Loaded image: (\w+)/\1/p')
                                docker push $image
                            '';
                            joined = 
                                builtins.concatStringsSep "\n" (
                                    builtins.map loadPush (builtins.attrValues self.images.${system})
                                );
                            scriptContents = 
                                ''
                                set -e
                                '' 
                                + joined;
                            script = pkgs.writeShellScript "push-images" scriptContents;
                        in
                        {
                            type = "app";
                            program = "${script}"; 
                        };
                };
            }
        );
}
