{
    inputs = {
        nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
        crane.url = "github:ipetkov/crane";
    };
    outputs = { self, nixpkgs, crane }: 
        let 
            system = "x86_64-linux";
            pkgs = nixpkgs.legacyPackages.${system};
            generatedBuild = import ./default.nix { inherit pkgs; };
        in
        {
            packages.${system} = rec {
                prism = generatedBuild.workspaceMembers.metric-collector.build;
                prismImage = pkgs.dockerTools.buildImage {
                    name = "prism";
                    tag = "latest";
                    copyToRoot = [ prism ];
                    config = {
                        Entrypoint = [ "/bin/metric-collector" ];
                    };
                };
            };
        };
}
