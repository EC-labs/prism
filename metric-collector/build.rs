use anyhow::Result;
use bindgen::Formatter;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::{env, fs};

use libbpf_cargo::SkeletonBuilder;

const SUBS: [&str; 7] = [
    "iowait",
    "vfs",
    "futex",
    "net",
    // "muxio",
    "mux",
    "taskstats",
    "discovery",
];

fn generate_linux_header_bindings(cargo_manifest_dir: &Path) -> Result<()> {
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
        .formatter(Formatter::Rustfmt)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_arg(format!("--target={}", env::var("HOST").unwrap()))
        .generate()
        .expect("Unable to generate linux header bindings");

    let out = cargo_manifest_dir.join("src/sub/include/linux/bindings.rs");

    bindings
        .write_to_file(out)
        .expect("Couldn't write linux bindings");
    Ok(())
}

fn generate_consts_header_bindings(cargo_manifest_dir: &Path) -> Result<()> {
    let common = cargo_manifest_dir.join("src/sub/include/consts.h");
    let bindings = bindgen::Builder::default()
        .header(common.to_str().unwrap())
        .formatter(Formatter::Rustfmt)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .clang_arg(format!("--target={}", env::var("HOST").unwrap()))
        .clang_args(["-I", "src/vmlinux"])
        .generate()?;

    let out = cargo_manifest_dir.join("src/sub/include/consts.bindings.rs");
    bindings.write_to_file(out)?;
    Ok(())
}

fn generate_sub_header_bindings(cargo_manifest_dir: &Path) -> Result<()> {
    for bind in ["taskstats", "muxio"] {
        let bindings = bindgen::Builder::default()
            .header(
                cargo_manifest_dir
                    .join(format!("src/sub/{bind}/bpf/{bind}.h"))
                    .to_str()
                    .unwrap(),
            )
            .formatter(Formatter::Rustfmt)
            .clang_arg(format!("--target={}", env::var("HOST").unwrap()))
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
    generate_consts_header_bindings(&cargo_manifest_dir)?;
    generate_sub_header_bindings(&cargo_manifest_dir)?;

    println!(
        "cargo:rerun-if-changed={}/src/sub/include/common.h",
        cargo_manifest_dir.to_str().unwrap()
    );
    println!(
        "cargo:rerun-if-changed={}/src/sub/include/vfs.h",
        cargo_manifest_dir.to_str().unwrap()
    );
    println!(
        "cargo:rerun-if-changed={}/src/sub/include/net.h",
        cargo_manifest_dir.to_str().unwrap()
    );

    eprintln!("{:?}", vmlinux::include_path_root().join(&arch));
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
