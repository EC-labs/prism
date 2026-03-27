{ pkgs, mkShell }:
{
    devShell = mkShell {
        packages = with pkgs; [ 
            nodejs 
            yarn 
            uv 
            (python3.withPackages (py-pkgs: with py-pkgs; [streamlit]))
        ];
    };
}

