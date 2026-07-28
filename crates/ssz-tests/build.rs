//! Build script generating the SSZ containers in `tests/ssz/delegate.ssz`.

use std::path::Path;

use ssz_codegen::{ModuleGeneration, build_ssz_files};

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
    let output_path = Path::new(&out_dir).join("generated_delegate_ssz.rs");

    let entry_points = ["delegate.ssz"];
    // No external crates: the schema's `import consumer` resolves to the
    // integration test's own `consumer` module, which declares the wrappers and
    // their view aliases.
    let crates: [&str; 0] = [];

    build_ssz_files(
        &entry_points,
        "tests/ssz/",
        &crates,
        output_path.to_str().expect("utf8 path"),
        ModuleGeneration::NestedModules,
    )
    .expect("failed to generate delegate SSZ test types");

    println!("cargo:rerun-if-changed=tests/ssz/delegate.ssz");
}
