{ pkgs ? import <nixpkgs> {}, crate2nixTools }:
    let
      lockfile = builtins.fromTOML (builtins.readFile ./Cargo.lock);
      gitDeps = (builtins.filter (pkg: (pkg ? source) && ((builtins.match ''git\+(.*)\?rev=([0-9a-f]+)(#.*)?'' pkg.source) != null)) lockfile.package);
      getGitMetadata = giturl: let reGroups = builtins.match ''git\+(.*)\?rev=([0-9a-f]+)(#.*)?'' giturl; in {
        url = builtins.elemAt reGroups 0;
        rev = builtins.elemAt reGroups 1;
      };

      gitSrcOverrides = builtins.listToAttrs (
        builtins.map
        (pkg: {
            name = pkg.name;
            value = attr: {
                src = builtins.fetchGit (getGitMetadata pkg.source);
            };
        })
        gitDeps
      );
      crateOverrides = {
          libbpf-sys = attrs: {
            buildInputs = with pkgs; [
                pkg-config
                libz
                elfutils
            ];
          };

          containerd-client = attrs: {
            buildInputs = with pkgs; [
                protobuf
            ];
          };

          metric-collector = attrs: {
            nativeBuildInputs = with pkgs; [
                rustfmt
                rust-analyzer
                rustc
                cargo
                pkg-config
                libclang.lib
                clang
                protobuf
            ];

            buildInputs = with pkgs; [
                duckdb
                openssl
                libz
                elfutils
            ];

            LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
            hardeningDisable = [ "stackprotector" "zerocallusedregs" ];

          };
          vmlinux = attrs: {
            postPatch = ''
                substituteInPlace \
                  src/lib.rs \
                  --replace-fail \
                  'env!("CARGO_MANIFEST_DIR")' \
                  \"$src\"
            '';
          };
      };
      keys = pkgs.lib.unique (builtins.attrNames crateOverrides) ++ (builtins.attrNames gitSrcOverrides);
      getOrDefault = key: set: default: if builtins.hasAttr key set then builtins.getAttr key set else default;
      crateOverridesMerged = builtins.listToAttrs (
          builtins.map
          (key: {
            name = key;
            value = attr:
              getOrDefault key crateOverrides (x: {}) attr
              // getOrDefault key gitSrcOverrides (x: {}) attr;
          })
          keys
      );

      customBuildRustCrateForPkgs = pkgs: pkgs.buildRustCrate.override {
        defaultCrateOverrides = pkgs.defaultCrateOverrides // crateOverridesMerged;
      };

      generatedCargoNix = import (
        (pkgs.callPackage crate2nixTools {}).generatedCargoNix {
          src = ./.;
          name = "prism";
          # When using crate2nix IFD, crate2nix will try to prefetch the dependencies that do not have their checksums in the Cargo.lock file.
          # Overriding the git crates' src attribute to use builtins.fetchgit and passing dummy hashes for these crates stops crate2nix from prefetching these crates.
          additionalCrateHashes = builtins.listToAttrs (
            builtins.map (pkg: let gitMetadata = getGitMetadata pkg.source; in {name = "git+${gitMetadata.url}?rev=${gitMetadata.rev}#${pkg.name}@${pkg.version}"; value = "";}) gitDeps
          );
        }
      );

    in pkgs.callPackage generatedCargoNix {
        buildRustCrateForPkgs = customBuildRustCrateForPkgs;
    }
