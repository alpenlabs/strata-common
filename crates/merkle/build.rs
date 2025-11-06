//! Build script for generating SSZ code from schema definitions

use std::{env, fs, path::Path};

#[cfg(feature = "ssz")]
use ssz_codegen::{ModuleGeneration, build_ssz_files};

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let generated_file = Path::new(&out_dir).join("generated_ssz.rs");

    // Only generate SSZ types when the ssz feature is enabled
    if env::var("CARGO_FEATURE_SSZ").is_ok() {
        #[cfg(feature = "ssz")]
        {
            let entry_points = ["proof.ssz", "mmr.ssz"];

            build_ssz_files(
                &entry_points,
                "ssz/",
                &[],
                generated_file.to_str().expect("valid path"),
                ModuleGeneration::NestedModules,
            )
            .expect("Failed to generate SSZ types");

            for entry_point in &entry_points {
                println!("cargo:rerun-if-changed=ssz/{entry_point}");
            }
        }
    } else {
        // Create empty file when ssz feature is not enabled
        fs::write(generated_file, "// SSZ feature not enabled\n").expect("Failed to write file");
    }
}
