let 
    pkgs = import <nixpkgs> { };
in 
with pkgs; stdenv.mkDerivation {
    name = "prism";
    hardeningDisable = [ "stackprotector" "zerocallusedregs" ];

    nativeBuildInputs = [ 
        rustfmt
        rust-analyzer
        rustc
        cargo
        elfutils
        libz
        pkg-config 
        libclang.lib
        clang
        bpftrace
        linuxHeaders
        zsh
        strace
        netcat-openbsd
        tcpdump
    ];

    buildInputs = [ 
        duckdb
        openssl
        protobuf
    ];

    LIBCLANG_PATH = "${libclang.lib}/lib";
}
