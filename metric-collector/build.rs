use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SUBS: [&str; 2] = ["iowait", "vfs"];

fn main() {
    for sub in SUBS {
        let out = PathBuf::from(
            env::var_os("CARGO_MANIFEST_DIR")
                .expect("CARGO_MANIFEST_DIR must be set in build script"),
        )
        .join("src")
        .join("sub")
        .join(sub)
        .join("bpf")
        .join(&format!("{sub}.skel.rs"));

        let arch = env::var("CARGO_CFG_TARGET_ARCH")
            .expect("CARGO_CFG_TARGET_ARCH must be set in build script");

        let src = format!("src/sub/{sub}/bpf/{sub}.bpf.c");

        SkeletonBuilder::new()
            .source(&src)
            .clang_args([
                OsStr::new("-I"),
                vmlinux::include_path_root().join(arch).as_os_str(),
            ])
            .build_and_generate(&out)
            .unwrap();
        println!("cargo:rerun-if-changed={src}");
    }
}
