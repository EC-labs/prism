{ pkgs, lib, mkShell }:
{
    devShell = mkShell {
        packages = with pkgs; [ 
            nodejs 
            yarn 
            uv 
            (python3.withPackages (py-pkgs: with py-pkgs; [streamlit]))
        ];
    };

    package = pkgs.buildNpmPackage {
        name = "thread-dynamics";
        nativeBuildInputs = with pkgs; [
            nodejs
            yarn
        ];
        src = ./.;
        npmDepsHash = "sha256-D7mu38qofFp3CHNiYIbEz9LJiAmH9pqGs3pE7QGRCnE=";
        buildPhase = ''
            npm run build
        '';
        installPhase = ''
            mv build $out
        '';
    };
}

