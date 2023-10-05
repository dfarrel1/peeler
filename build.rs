fn main() {
    if cfg!(target_arch = "aarch64") && cfg!(feature = "static_linking") {
        println!("cargo:rustc-link-search=native=/usr/lib/aarch64-linux-gnu");
        println!("cargo:rustc-link-lib=static=cap");
    }
    if cfg!(target_arch = "x86_64") && cfg!(feature = "static_linking") {
        println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");
        println!("cargo:rustc-link-lib=static=cap");
    }
}
