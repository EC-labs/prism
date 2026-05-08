{
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
        flake-utils.url = "github:numtide/flake-utils";
        crate2nix = {
            url = "github:landaudiogo/crate2nix";
            inputs.nixpkgs.follows = "nixpkgs";
        };

        pyproject-nix = {
          url = "github:pyproject-nix/pyproject.nix";
          inputs.nixpkgs.follows = "nixpkgs";
        };

        uv2nix = {
          url = "github:pyproject-nix/uv2nix";
          inputs.pyproject-nix.follows = "pyproject-nix";
          inputs.nixpkgs.follows = "nixpkgs";
        };

        pyproject-build-systems = {
          url = "github:pyproject-nix/build-system-pkgs";
          inputs.pyproject-nix.follows = "pyproject-nix";
          inputs.uv2nix.follows = "uv2nix";
          inputs.nixpkgs.follows = "nixpkgs";
        };
    };
    outputs = { self, nixpkgs, flake-utils, crate2nix, pyproject-nix, uv2nix, pyproject-build-systems, ... }@inputs: 
        let 
            systems = [ "x86_64-linux" "aarch64-linux" ];
        in
        flake-utils.lib.eachSystem systems (system:
            let 
                pkgs = nixpkgs.legacyPackages.${system};
                crate2nixTools = crate2nix.lib.tools;
                generatedBuild = import ./default.nix { inherit pkgs crate2nixTools; };
                threadDynamicsComponent = (pkgs.callPackage ./analysis/src/components/thread_dynamics/frontend {});
                tag = self.shortRev or self.dirtyShortRev;
                analysis = import ./analysis { 
                    inherit tag pkgs pyproject-build-systems pyproject-nix uv2nix;
                    lib = pkgs.lib; 
                    threadDynamics = threadDynamicsComponent.package;
                };
                scripts = import ./scripts { inherit pkgs; };
                deploy = pkgs.callPackage ./deploy { inherit tag; };
            in {
                packages = {
                    prism = generatedBuild.workspaceMembers.metric-collector.build;
                    default = self.packages.${system}.prism;
                    ripple = self.packages.${system}.prism;
                    analysis = analysis.package;
                    analysisComponents.threadDynamics = threadDynamicsComponent.package;
                    combinedbs = scripts.packages.combinedbs;
                    prism-chart = deploy.packages.helmChart;
                };

                images = {
                    prism-agent = pkgs.dockerTools.buildImage {
                        name = "prism-agent";
                        inherit tag;
                        copyToRoot = [ self.packages.${system}.prism ];
                        config = {
                            Entrypoint = [ "/bin/metric-collector" ];
                        };
                    };
                    ripple-agent = pkgs.dockerTools.buildImage {
                        name = "ripple-agent";
                        inherit tag;
                        copyToRoot = [ self.packages.${system}.ripple ];
                        config = {
                            Entrypoint = [ "/bin/metric-collector" ];
                        };
                    };
                    analysis = analysis.image;
                };

                devShells = {
                    default = with pkgs; mkShell {
                        name = "prism";
                        hardeningDisable = [ "stackprotector" "zerocallusedregs" ];

                        nativeBuildInputs = [ 
                            dive
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
                            cargo-flamegraph
                            clickhouse
                        ];

                        buildInputs = [ 
                            duckdb
                            openssl
                            protobuf
                            rdkafka
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
                    analysis = analysis.devShell;
                    analysisComponents.threadDynamics = threadDynamicsComponent.devShell;
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
                    deploy = deploy.devShell;
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
                    analysis = {
                        type = "app";
                        program = "${self.packages.${system}.analysis}/bin/analysis";
                    };
                    combinedbs = {
                        type = "app";
                        program = "${scripts.packages.combinedbs}/bin/combinedbs";
                    };
                    pushImages = 
                        let
                            loadPush = imageDerivation: ''
                                image=$(docker load < ${imageDerivation} | sed -nE 's/Loaded image: (\w+)/\1/p')
                                docker tag "$image" "$repository/$image"
                                docker push "$repository/$image"
                            '';
                            joined = 
                                builtins.concatStringsSep "\n" (
                                    builtins.map loadPush (builtins.attrValues self.images.${system})
                                );
                            scriptContents = 
                                ''
                                set -e

                                if (( $# != 1 )); then
                                    echo "Missing repository argument (e.g. `dclandau` for a docker hub account)";
                                    exit 1;
                                fi

                                repository="$1"
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
