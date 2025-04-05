let 
    pkgs = import <nixpkgs> { };
in 
with pkgs; stdenv.mkDerivation {
    name = "prism";
    hardeningDisable = [ "stackprotector" "zerocallusedregs" ];

    nativeBuildInputs = [ 
        rustc
        cargo
        elfutils
        libz
        pkg-config 
        libclang.lib
    ];
    buildInputs = [ 
        duckdb
        openssl
    ];

    LIBCLANG_PATH = "${libclang.lib}/lib";
}
