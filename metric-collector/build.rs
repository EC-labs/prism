use anyhow::Result;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::{env, fs};

use libbpf_cargo::SkeletonBuilder;

const SUBS: [&str; 6] = ["iowait", "vfs", "futex", "net", "muxio", "taskstats"];

fn generate_linux_header_bindings(cargo_manifest_dir: &PathBuf) -> Result<()> {
    let dir = cargo_manifest_dir.join("src/sub/include/linux");
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

    let out = cargo_manifest_dir.join("src/sub/include/linux/bindings.rs");

    bindings
        .write_to_file(out)
        .expect("Couldn't write linux bindings");
    Ok(())
}

fn generate_consts_header_bindings(cargo_manifest_dir: &PathBuf, arch: &str) -> Result<()> {
    let common = cargo_manifest_dir.join("src/sub/include/consts.h");
    let bindings = bindgen::Builder::default()
        .header(common.to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_args([
            "-I",
            vmlinux::include_path_root().join(arch).to_str().unwrap(),
        ])
        .generate()?;

    let out = cargo_manifest_dir.join("src/sub/include/consts.bindings.rs");
    bindings.write_to_file(out)?;
    Ok(())
}

fn generate_sub_header_bindings(cargo_manifest_dir: &PathBuf) -> Result<()> {
    for bind in ["taskstats", "muxio"] {
        let bindings = bindgen::Builder::default()
            .header(
                cargo_manifest_dir
                    .join(format!("src/sub/{bind}/bpf/{bind}.h"))
                    .to_str()
                    .unwrap(),
            )
            .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
            .generate()?;

        let out = cargo_manifest_dir.join(format!("src/sub/{bind}"));
        bindings.write_to_file(out.join(format!("{bind}.bindings.rs")))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("missing CARGO_CFG_TARGET_ARCH");
    let cargo_manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("missing CARGO_MANIFEST_DIR"));
    let include_common = cargo_manifest_dir.join("src/sub/include");

    generate_linux_header_bindings(&cargo_manifest_dir)?;
    generate_consts_header_bindings(&cargo_manifest_dir, &arch)?;
    generate_sub_header_bindings(&cargo_manifest_dir)?;

    println!(
        "cargo:rerun-if-changed={}/src/sub/include/common.h",
        cargo_manifest_dir.to_str().unwrap()
    );
    println!(
        "cargo:rerun-if-changed={}/src/sub/include/vfs.h",
        cargo_manifest_dir.to_str().unwrap()
    );

    for sub in SUBS {
        let out = cargo_manifest_dir.join(format!("src/sub/{sub}/bpf/{sub}.skel.rs"));

        let src = format!("src/sub/{sub}/bpf/{sub}.bpf.c");
        SkeletonBuilder::new()
            .source(&src)
            .clang_args([
                OsStr::new("-I"),
                vmlinux::include_path_root().join(&arch).as_os_str(),
                OsStr::new("-I"),
                include_common.as_os_str(),
            ])
            .build_and_generate(&out)
            .unwrap();
        println!("cargo:rerun-if-changed={src}");
    }

    Ok(())
}
