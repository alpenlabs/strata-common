//! Build script for generating SSZ code from schema definitions

use std::path::Path;

use ssz_codegen::{ModuleGeneration, build_ssz_files};

fn main() {
    // Generate SSZ types for Moho into OUT_DIR
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
    let output_path = Path::new(&out_dir).join("generated_ssz.rs");

    // Use local ssz-gen codegen
    let entry_points = ["key.ssz"]; // ssz/key.ssz
    let base_dir = "ssz/"; // relative to this crate root
    // External crates whose SSZ modules are imported by `key.ssz`
    let crates = [];

    build_ssz_files(
        &entry_points,
        base_dir,
        &crates,
        output_path.to_str().expect("utf8 path"),
        ModuleGeneration::NestedModules,
    )
    .expect("Failed to generate SSZ types");
}
