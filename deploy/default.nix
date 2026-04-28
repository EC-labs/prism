{ pkgs, lib, stdenv, tag, ... }:
let
    helmDependencies = stdenv.mkDerivation {
        name = "prism-chart-deps";

        outputHashAlgo = "sha256";
        outputHashMode = "recursive";
        # outputHash = lib.fakeHash;
        outputHash = "sha256-z/EOANvScQvq7HJ4hpBDhyOdeDQbpGGA9BfOSQxCgCg=";

        buildInputs = with pkgs; [
            kubernetes-helm
            yq
            jq
        ];

        src = ./prism-chart;
        buildPhase = ''
            helm dependency build;
        '';

        installPhase = ''
            mv charts $out
        '';
    };
in
{
    devShell = pkgs.mkShell {
        packages = with pkgs; [ 
            kubernetes-helm
            kubectl
        ];

        KUBECONFIG = "./remote-admin.conf";
    };
    packages = rec {
        # helmRelease is the zipped helm chart
        helmRelease = stdenv.mkDerivation {
            name = "prism-chart-release";
            version = tag;
            src = ./prism-chart;
            buildInputs = with pkgs; [
                kubernetes-helm
                yq
                jq
            ];

            buildPhase = ''
                yq -i -y '.prism.tag = "${tag}"' values.yaml
                ln -s ${helmDependencies} ./charts
                helm package ./
            '';

            installPhase = ''
                mv prism-chart-* $out
            '';
        };

        # helm
        helmChart = stdenv.mkDerivation {
            name = "prism-chart";
            version = tag;
            dontUnpack = true;
            dontBuild = true;

            installPhase = ''
                mkdir $out
                tar -xvzf "${helmRelease}" -C $out
            '';
        };
    };
}
