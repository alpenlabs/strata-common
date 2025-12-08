//! Benchmark for MMR implementations.
#![allow(missing_docs)]
#![allow(unused_crate_dependencies)]

// stupid linter issue
use criterion as _;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use sha2::{Digest, Sha256};
use strata_merkle::{Sha256Hasher, ext::Mmr, mmr::CompactMmr64};

type Hash32 = [u8; 32];

/// Generates random 32-byte hashes using SHA256 of sequential indices.
fn generate_random_hashes(count: usize) -> Vec<Hash32> {
    (0..count)
        .map(|i| {
            let mut hasher = Sha256::new();
            hasher.update(i.to_le_bytes());
            hasher.finalize().into()
        })
        .collect()
}

/// Benchmark for the CompactMmr64 implementation (alternative name).
fn bench_mmr_state_vec(c: &mut Criterion, size: usize, hashes: Vec<Hash32>) {
    let group_name = format!("compact_mmr64_alt_{}", size);
    c.bench_with_input(BenchmarkId::new(&group_name, size), &hashes, |b, hashes| {
        b.iter(|| {
            let mut mmr = CompactMmr64::<Hash32>::new(64);
            for hash in hashes.iter() {
                Mmr::<Sha256Hasher>::add_leaf(&mut mmr, *hash).expect("add_leaf failed");
            }
            black_box(mmr);
        });
    });
}

/// Benchmark for the CompactMmr64 implementation.
fn bench_compact_mmr(c: &mut Criterion, size: usize, hashes: Vec<Hash32>) {
    let group_name = format!("compact_mmr_{}", size);
    c.bench_with_input(BenchmarkId::new(&group_name, size), &hashes, |b, hashes| {
        b.iter(|| {
            let mut mmr = CompactMmr64::<Hash32>::new(64);
            for hash in hashes.iter() {
                Mmr::<Sha256Hasher>::add_leaf(&mut mmr, *hash).expect("add_leaf failed");
            }
            black_box(mmr);
        });
    });
}

/// Benchmark for inserting into a large pre-populated CompactMmr64.
fn bench_mmr_state_vec_large_base(
    c: &mut Criterion,
    base_size: usize,
    insert_size: usize,
    hashes: Vec<Hash32>,
) {
    println!("Pre-populating CompactMmr64 with {} entries...", base_size);
    let mut base_mmr = CompactMmr64::<Hash32>::new(64);

    let base_hashes = generate_random_hashes(base_size);
    for hash in base_hashes.iter() {
        Mmr::<Sha256Hasher>::add_leaf(&mut base_mmr, *hash).expect("add_leaf failed");
    }

    let group_name = format!(
        "compact_mmr64_{}M_to_{}M",
        base_size / 1_000_000,
        (base_size + insert_size) / 1_000_000
    );

    c.bench_with_input(
        BenchmarkId::new(&group_name, insert_size),
        &hashes,
        |b, hashes| {
            b.iter(|| {
                let mut mmr = base_mmr.clone();
                for hash in hashes.iter() {
                    Mmr::<Sha256Hasher>::add_leaf(&mut mmr, *hash).expect("add_leaf failed");
                }
                black_box(mmr);
            });
        },
    );
}

fn benchmark_mmr_implementations(c: &mut Criterion) {
    // Pre-generate test data for each size
    let sizes = [1000, 100_000, 10_000_000];

    for &size in &sizes {
        println!("Generating {size} random hashes...");
        let hashes = generate_random_hashes(size);

        println!("Benchmarking CompactMmr64 with {size} entries...");
        bench_mmr_state_vec(c, size, hashes.clone());

        println!("Benchmarking CompactMmr64 with {size} entries...");
        bench_compact_mmr(c, size, hashes);
    }

    // Large base benchmark: 34M -> 35M (inserting 1M into 34M)
    let base_size_m = 34;
    let insert_size_m = 1;
    let mult = 1_000_000;
    let total_m = base_size_m + insert_size_m;

    let base_size = base_size_m * mult;
    let insert_size = insert_size_m * mult;

    println!("\nGenerating {insert_size_m}M hashes for large base benchmark...",);
    let insert_hashes = generate_random_hashes(insert_size);

    println!("Benchmarking CompactMmr64: {base_size_m}M -> {total_m}M entries...",);
    bench_mmr_state_vec_large_base(c, base_size, insert_size, insert_hashes);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(15);
    targets = benchmark_mmr_implementations
}
criterion_main!(benches);
