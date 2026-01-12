{ pkgs ? import <nixpkgs> {} }:
{
    devShell = pkgs.mkShell {
        packages = with pkgs; [
            nodejs
            yarn
        ];
    };

    package = pkgs.buildNpmPackage {
        name = "sql-editor";
        nativeBuildInputs = with pkgs; [
            nodejs
            yarn
            zip
        ];
        src = ./.;
        npmDepsHash = "sha256-eW1LOkk1qYvafkUO25C5U9f2fb/Fzx88Nz0WKRiqM9I=";
        buildPhase = ''
            npm run build
        '';
        installPhase = ''
            mv build $out
        '';
    };
}
