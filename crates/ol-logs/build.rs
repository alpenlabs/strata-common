//! Build script generating the SSZ `OLLog` container from `ssz/log.ssz`.

use std::path::Path;

use ssz_codegen::{ModuleGeneration, build_ssz_files};

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
    let output_path = Path::new(&out_dir).join("generated_ssz.rs");

    let entry_points = ["log.ssz"];
    // External crates whose SSZ modules are imported by `log.ssz`.
    let crates = ["strata_identifiers"];

    build_ssz_files(
        &entry_points,
        "ssz/",
        &crates,
        output_path.to_str().expect("utf8 path"),
        ModuleGeneration::NestedModules,
    )
    .expect("Failed to generate SSZ types");

    println!("cargo:rerun-if-changed=ssz/log.ssz");
}
