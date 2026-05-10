//! Mollusk-driven CU benchmark for `halo2-solana-verifier-program`.
//!
//! Loads the `.so` produced by `cargo build-sbf`, invokes it with the golden
//! test vector, and prints `compute_units_consumed`. This is also the first
//! place where the BPF-stack-frame-warning real-runtime question gets
//! answered: if the program runs and verifies, the warnings are conservative;
//! if it panics, we need to refactor for stack budget.
//!
//! Run with: `cargo build-sbf -p halo2-solana-verifier-program --features bpf-entrypoint`
//!           then `cargo test -p halo2-solana-verifier-program --test cu_bench -- --nocapture`

use mollusk_svm::{Mollusk, result::ProgramResult};
use solana_program::{instruction::Instruction, pubkey::Pubkey};
use std::path::PathBuf;

/// Read the golden test vector created by `gen-proof --write-golden`.
fn load_golden_instruction_data() -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../circuits/standard-plonk/tests/golden_v1.bin");
    std::fs::read(&path)
        .unwrap_or_else(|_| panic!(
            "missing {:?}\n\
             Generate it first:\n\
             cargo run -p standard-plonk-circuit --bin gen-proof -- --write-golden",
            path,
        ))
}

#[test]
fn verify_golden_vector_inside_bpf_vm() {
    let instruction_data = load_golden_instruction_data();
    let program_id = Pubkey::new_unique();

    // `Mollusk::new` searches `tests/fixtures` (and a few other paths) for
    // `halo2_solana_verifier_program.so`. We symlink target/deploy/*.so
    // into tests/fixtures so the .so produced by `cargo build-sbf` is picked
    // up automatically.
    let mut mollusk = Mollusk::new(&program_id, "halo2_solana_verifier_program");
    // Crank the CU budget WAY past Solana's 1.4M default so we can observe
    // the true cost of verify(). For mainnet today, this verifier would
    // need either a CU-limit raise, request_compute_units, or the
    // alt_bn128_g1_msm SIMD landing — all of which are part of the
    // strategic case this PoC is making.
    mollusk.compute_budget.compute_unit_limit = 1_000_000_000;
    // Pinocchio's default bump allocator NEVER frees, so verifier Vec churn
    // accumulates. Bump the heap to Solana's max (256 KB) — that's what
    // `ComputeBudgetInstruction::request_heap_frame(256 * 1024)` would do
    // on mainnet too.
    mollusk.compute_budget.heap_size = 256 * 1024;

    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, vec![]);

    let result = mollusk.process_instruction(&instruction, &[]);

    eprintln!("[bench] program_result        = {:?}", result.program_result);
    eprintln!("[bench] raw_result            = {:?}", result.raw_result);
    eprintln!("[bench] compute_units_consumed = {}", result.compute_units_consumed);

    // The fundamental question: does the BPF VM accept our stack-frame-heavy
    // verifier? If it panics with stack overflow, we need to refactor.
    match result.program_result {
        ProgramResult::Success => {
            eprintln!("[bench] ✓ verifier ran end-to-end inside BPF VM");
        }
        ProgramResult::Failure(err) => {
            panic!(
                "BPF program failed inside VM: {err:?}\n\
                 (Likely the stack-frame-warning case from `cargo build-sbf`.)"
            );
        }
        ProgramResult::UnknownError(err) => {
            panic!("BPF program errored: {err:?}");
        }
    }
}
