fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").ok();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").ok();
    if os.as_deref() == Some("macos") && arch.as_deref() == Some("aarch64") {
        println!("cargo:rustc-link-lib=framework=IOKit");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
}
