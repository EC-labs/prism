{ pkgs, pyproject-build-systems, pyproject-nix, lib, uv2nix }:
let 
      python = pkgs.python312;
      workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./.; };
      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel";
      };
      pythonSet = (pkgs.callPackage pyproject-nix.build.packages { inherit python; }).overrideScope
          (
            lib.composeManyExtensions [
              pyproject-build-systems.overlays.wheel
              overlay
            ]
          );
      virtualenv = pythonSet.mkVirtualEnv "dev-env" workspace.deps.all;
in
pkgs.mkShell {
    packages = [
      python
      pkgs.uv
      virtualenv
    ];
    env = {
      UV_NO_SYNC = "1";
      UV_PYTHON = pythonSet.python.interpreter;
      UV_PYTHON_DOWNLOADS = "never";
      LD_LIBRARY_PATH = lib.makeLibraryPath pkgs.pythonManylinuxPackages.manylinux1;
    };
    shellHook = ''
      unset PYTHONPATH
      source "${virtualenv}/bin/activate"
    '';
}
