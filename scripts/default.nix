{ pkgs ? import <nixpkgs> {} }:
rec {
    packages = {
        combinedbs = pkgs.stdenv.mkDerivation {
          name = "myscript";
          buildInputs = [
            (pkgs.python3.withPackages (pythonPackages: with pythonPackages; [
              duckdb
              click
            ]))
          ];
          dontUnpack = true;
          installPhase = "install -Dm755 ${./combinedbs.py} $out/bin/combinedbs";
        };
    };
}
