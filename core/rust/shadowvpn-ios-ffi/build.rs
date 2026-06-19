use std::env;
use std::path::PathBuf;

fn main() {
    // Re-run only when source files or the cbindgen config change.
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=cbindgen.toml");

    // Skip header generation during rust-analyzer / IDE indexing passes so the
    // editor doesn't churn `include/shadowvpn_core.h` on every keystroke. The
    // build-rust.sh release build clears this var so the header is regenerated.
    if env::var("CBINDGEN_SKIP").is_ok() {
        return;
    }

    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let config = cbindgen::Config::from_file(PathBuf::from(&crate_dir).join("cbindgen.toml"))
        .unwrap_or_default();

    let out = PathBuf::from(&crate_dir)
        .join("include")
        .join("shadowvpn_core.h");
    std::fs::create_dir_all(out.parent().unwrap()).ok();

    if let Ok(bindings) = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        bindings.write_to_file(&out);
    }
}
