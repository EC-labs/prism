use anyhow::Result;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::{env, fs};

use libbpf_cargo::SkeletonBuilder;

const SUBS: [&str; 6] = ["iowait", "vfs", "futex", "net", "muxio", "taskstats"];

fn generate_linux_header_bindings() -> Result<()> {
    let dir = "src/sub/include/linux";
    let headers: Vec<_> = fs::read_dir(dir)?
        .map(|dentry| {
            String::from(
                dentry
                    .unwrap()
                    .path()
                    .to_str()
                    .expect("unable to convert path to &str"),
            )
        })
        .filter(|filename| filename.ends_with(".h"))
        .collect();

    let bindings = bindgen::Builder::default()
        .headers(headers)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate linux header bindings");

    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src/sub/include/linux/bindings.rs");

    bindings
        .write_to_file(out)
        .expect("Couldn't write linux bindings");
    Ok(())
}

fn main() -> Result<()> {
    generate_linux_header_bindings()?;
    let bindings = bindgen::Builder::default()
        .header("src/sub/taskstats/bpf/taskstats.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("sub")
    .join("taskstats");
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("Couldn't write bindings!");

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

    Ok(())
}
