use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SUBS: [&str; 6] = ["iowait", "vfs", "futex", "net", "muxio", "taskstats"];

fn main() {
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/sub/taskstats/bpf/taskstats.h")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
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
}
