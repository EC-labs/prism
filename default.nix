let 
    pkgs = import <nixpkgs> {};
in rec {
    prism = import ./prism.nix { inherit pkgs; lib = pkgs.lib; };
    prismDockerImage = pkgs.dockerTools.buildImage {
        name = "prism";
        tag = "latest";
        copyToRoot = [ prism ];
        config = {
            Entrypoint = [ "/bin/metric-collector" ];
        };
    };
}
