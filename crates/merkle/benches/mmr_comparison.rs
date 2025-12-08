//! Benchmark comparing old and new MMR implementations.
#![allow(missing_docs)]
#![allow(unused_crate_dependencies)]
#![allow(deprecated)] // Uses MerkleMr64 for comparison benchmarks

// stupid linter issue
use criterion as _;

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use sha2::{Digest, Sha256};
use strata_merkle::{Sha256Hasher, mmr::MerkleMr64, new_mmr::Mmr, new_state::NewMmrState};

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

/// Benchmark for the old MMR implementation (MerkleMr64).
fn bench_old_mmr(c: &mut Criterion, size: usize, hashes: Vec<Hash32>) {
    let group_name = format!("old_mmr_{}", size);
    c.bench_with_input(BenchmarkId::new(&group_name, size), &hashes, |b, hashes| {
        b.iter(|| {
            // Calculate required capacity (log2 of size, rounded up)
            let cap_log2 = (size as f64).log2().ceil() as usize;
            let mut mmr = MerkleMr64::<Sha256Hasher>::new(cap_log2.max(1));
            for hash in hashes.iter() {
                mmr.add_leaf(*hash).expect("add_leaf failed");
            }
            black_box(mmr);
        });
    });
}

/// Benchmark for the new MMR implementation (NewMmrState + Mmr trait).
fn bench_new_mmr(c: &mut Criterion, size: usize, hashes: Vec<Hash32>) {
    let group_name = format!("new_mmr_{}", size);
    c.bench_with_input(BenchmarkId::new(&group_name, size), &hashes, |b, hashes| {
        b.iter(|| {
            let mut mmr: NewMmrState<Hash32> = NewMmrState::new_empty();
            for hash in hashes.iter() {
                Mmr::<Sha256Hasher>::add_leaf(&mut mmr, *hash).expect("add_leaf failed");
            }
            black_box(mmr);
        });
    });
}

/// Benchmark for inserting into a large pre-populated old MMR.
fn bench_old_mmr_large_base(
    c: &mut Criterion,
    base_size: usize,
    insert_size: usize,
    hashes: Vec<Hash32>,
) {
    println!("Pre-populating old MMR with {} entries...", base_size);
    let cap_log2 = ((base_size + insert_size) as f64).log2().ceil() as usize;
    let mut base_mmr = MerkleMr64::<Sha256Hasher>::new(cap_log2.max(1));

    let base_hashes = generate_random_hashes(base_size);
    for hash in base_hashes.iter() {
        base_mmr.add_leaf(*hash).expect("add_leaf failed");
    }

    let group_name = format!(
        "old_mmr_{}M_to_{}M",
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
                    mmr.add_leaf(*hash).expect("add_leaf failed");
                }
                black_box(mmr);
            });
        },
    );
}

/// Benchmark for inserting into a large pre-populated new MMR.
fn bench_new_mmr_large_base(
    c: &mut Criterion,
    base_size: usize,
    insert_size: usize,
    hashes: Vec<Hash32>,
) {
    println!("Pre-populating new MMR with {} entries...", base_size);
    let mut base_mmr = NewMmrState::<Hash32>::new_empty();

    let base_hashes = generate_random_hashes(base_size);
    for hash in base_hashes.iter() {
        Mmr::<Sha256Hasher>::add_leaf(&mut base_mmr, *hash).expect("add_leaf failed");
    }

    let group_name = format!(
        "new_mmr_{}M_to_{}M",
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

        println!("Benchmarking old MMR with {size} entries...");
        bench_old_mmr(c, size, hashes.clone());

        println!("Benchmarking new MMR with {size} entries...");
        bench_new_mmr(c, size, hashes);
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

    println!("Benchmarking old MMR: {base_size_m}M -> {total_m}M entries...",);
    bench_old_mmr_large_base(c, base_size, insert_size, insert_hashes.clone());

    println!("Benchmarking new MMR: {base_size_m}M -> {total_m}M entries...",);
    bench_new_mmr_large_base(c, base_size, insert_size, insert_hashes);
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(15);
    targets = benchmark_mmr_implementations
}
criterion_main!(benches);
