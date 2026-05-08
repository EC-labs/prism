{ pkgs, pyproject-build-systems, pyproject-nix, lib, uv2nix, threadDynamics, tag }:
let 
      python = pkgs.python312;
      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };
      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel";
      };
      pyprojectOverrides = final: prev: {
        src = prev.src.overrideAttrs(old: {
          inherit threadDynamics;
          preBuild = ''
            pushd src/components/thread_dynamics/frontend
            cp -r $threadDynamics ./build
            popd
          '';
        });
      };
      pythonSet = (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).overrideScope
          (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.wheel
              overlay
              pyprojectOverrides
            ]
          );
      virtualenv = pythonSet.mkVirtualEnv "dev-env" workspace.deps.all;
      sqlEditor = (pkgs.callPackage ./src/components/monaco_sql_editor/frontend { }).package;
in
rec {
    devShell = pkgs.mkShell {
        packages = [
          python
          pkgs.uv
          virtualenv
        ];
        env = {
          UV_NO_SYNC = "1";
          UV_PYTHON = pythonSet.python.interpreter;
          UV_PYTHON_DOWNLOADS = "never";
          SQL_EDITOR = sqlEditor;
          LD_LIBRARY_PATH = lib.makeLibraryPath pkgs.pythonManylinuxPackages.manylinux1;
        };
        shellHook = ''
          unset PYTHONPATH
          source "${virtualenv}/bin/activate"
        '';
    };
    package = pkgs.writeShellScriptBin "analysis" ''
        source ${virtualenv}/bin/activate
        export SQL_EDITOR=${sqlEditor}
        ${virtualenv}/bin/analysis
    '';
    image = pkgs.dockerTools.buildImage {
        name = "prism-analysis";
        inherit tag;
        copyToRoot = [ package pkgs.coreutils ];
        config = {
            Entrypoint = [ "/bin/analysis" ];
        };
    };
}
