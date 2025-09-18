use cc;

fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=src/direct-read.c");
    // Use the `cc` crate to build a C file and statically link it.
    cc::Build::new()
        .file("src/direct-read.c")
        .compile("direct-read");
}
