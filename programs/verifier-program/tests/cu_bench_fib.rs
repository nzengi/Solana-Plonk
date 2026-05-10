//! Mollusk CU benchmark for the Fibonacci circuit (v1.5).
//!
//! Loads `circuits/fibonacci/tests/golden_v15_fib.bin`, parses the
//! GLDN0002 layout (which includes a public-inputs section), reassembles
//! it into the program's existing data-account format, and runs the BPF
//! verifier under Mollusk.

use mollusk_svm::{Mollusk, result::ProgramResult};
use solana_program::{
    instruction::Instruction,
    pubkey::Pubkey,
};
use std::path::PathBuf;

const PROGRAM_NAME: &str = "halo2_solana_verifier_program";

/// Layout of `golden_v15_fib.bin` (emitted by `gen-fib-proof --write-golden`):
/// ```text
///   magic        : "GLDN0002" (8 B)
///   vk_len  u32 LE,   vk_bytes
///   proof_len u32 LE, proof_bytes
///   g1_one (64 B), g2_one (128 B), g2_tau (128 B)
///   n_pi    u32 LE,   pi_bytes (32 B each)
/// ```
fn load_fib_golden() -> (Vec<u8>, Vec<u8>, [u8; 64], [u8; 128], [u8; 128], Vec<[u8; 32]>) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../circuits/fibonacci/tests/golden_v15_fib.bin");
    let buf = std::fs::read(&path).unwrap_or_else(|_| panic!(
        "missing {path:?} — run \
         `cargo run -p fibonacci-circuit --bin gen-fib-proof -- --write-golden` first"
    ));
    let mut cur = 0;
    assert_eq!(&buf[cur..cur + 8], b"GLDN0002", "bad Fibonacci golden magic");
    cur += 8;

    let vk_len = u32::from_le_bytes([buf[cur], buf[cur+1], buf[cur+2], buf[cur+3]]) as usize;
    cur += 4;
    let vk = buf[cur..cur + vk_len].to_vec();
    cur += vk_len;

    let proof_len = u32::from_le_bytes([buf[cur], buf[cur+1], buf[cur+2], buf[cur+3]]) as usize;
    cur += 4;
    let proof = buf[cur..cur + proof_len].to_vec();
    cur += proof_len;

    let mut g1_one = [0u8; 64];
    g1_one.copy_from_slice(&buf[cur..cur + 64]);
    cur += 64;
    let mut g2_one = [0u8; 128];
    g2_one.copy_from_slice(&buf[cur..cur + 128]);
    cur += 128;
    let mut g2_tau = [0u8; 128];
    g2_tau.copy_from_slice(&buf[cur..cur + 128]);
    cur += 128;

    let n_pi = u32::from_le_bytes([buf[cur], buf[cur+1], buf[cur+2], buf[cur+3]]) as usize;
    cur += 4;
    let mut pis = Vec::with_capacity(n_pi);
    for _ in 0..n_pi {
        let mut pi = [0u8; 32];
        pi.copy_from_slice(&buf[cur..cur + 32]);
        pis.push(pi);
        cur += 32;
    }
    assert_eq!(cur, buf.len(), "trailing bytes in Fibonacci golden file");
    (vk, proof, g1_one, g2_one, g2_tau, pis)
}

/// Repackage to the verifier program's instruction-data format (the
/// existing `GLDN0001` layout — vk + proof + 3 G1/G2 fields, no public
/// inputs section because v1.5 verifier reads them from a separate slot).
/// Public inputs are embedded by **appending** them after the kzg_g2_tau
/// region; the verifier-program parser already rejects trailing bytes,
/// so we either:
///   (a) extend the program parser to accept an n_pi suffix, OR
///   (b) ride the existing `instruction_data` path with no PIs.
///
/// (b) is fine for "Fibonacci with PI = target=21" — the program's
/// `parse_instruction` v1 layout passes `&[]` for public_inputs, but
/// the verifier crate's `verify(...)` accepts public_inputs as a separate
/// argument. To keep this PoC tight, we extend `parse_instruction` to
/// accept an optional public-inputs suffix.
fn build_legacy_payload(
    vk: &[u8], proof: &[u8],
    g1_one: &[u8; 64], g2_one: &[u8; 128], g2_tau: &[u8; 128],
    pis: &[[u8; 32]],
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"GLDN0001");
    out.extend_from_slice(&(vk.len() as u32).to_le_bytes());
    out.extend_from_slice(vk);
    out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    out.extend_from_slice(proof);
    out.extend_from_slice(g1_one);
    out.extend_from_slice(g2_one);
    out.extend_from_slice(g2_tau);
    // Public inputs as an n_pi u32 LE prefix + 32 B each.
    out.extend_from_slice(&(pis.len() as u32).to_le_bytes());
    for pi in pis { out.extend_from_slice(pi); }
    out
}

#[test]
fn fibonacci_verify_inside_bpf_vm() {
    let (vk, proof, g1_one, g2_one, g2_tau, pis) = load_fib_golden();
    let instruction_data = build_legacy_payload(&vk, &proof, &g1_one, &g2_one, &g2_tau, &pis);

    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&program_id, PROGRAM_NAME);
    mollusk.compute_budget.compute_unit_limit = 1_000_000_000;
    mollusk.compute_budget.heap_size = 256 * 1024;

    // Mollusk doesn't enforce Solana's 1232-byte tx limit; pass the full
    // golden vector through `instruction_data` directly, just like the
    // StandardPlonk cu_bench does.
    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, vec![]);
    let result = mollusk.process_instruction(&instruction, &[]);
    eprintln!("[fib] program_result        = {:?}", result.program_result);
    eprintln!("[fib] compute_units_consumed = {}", result.compute_units_consumed);

    match result.program_result {
        ProgramResult::Success => eprintln!("[fib] ✓ Fibonacci verifier passed inside BPF VM"),
        other => panic!("Fibonacci BPF run failed: {other:?}"),
    }
}
