{
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
        flake-utils.url = "github:numtide/flake-utils";
    };
    outputs = { self, nixpkgs, flake-utils }: 
        let 
            systems = [ "x86_64-linux" "aarch64-linux" ];
        in
        flake-utils.lib.eachSystem systems (system:
            let 
                pkgs = nixpkgs.legacyPackages.${system};
                generatedBuild = import ./default.nix { inherit pkgs; };
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
            }
        );
}
