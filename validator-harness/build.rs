use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let build_dir = manifest_dir.join("../build");
    println!("cargo:rustc-link-search=native={}", build_dir.display());
    println!("cargo:rustc-link-lib=static=dethv");
    println!("cargo:rustc-link-lib=pthread");
    println!("cargo:rerun-if-changed=../build/libdethv.a");
    println!("cargo:rerun-if-changed=../include/dethv.h");
}
