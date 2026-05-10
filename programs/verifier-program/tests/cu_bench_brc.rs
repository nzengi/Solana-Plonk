//! Mollusk CU benchmark for the bound-range-check circuit (Phase 2).
//!
//! This circuit binds a range-check Plookup proof to a claimer pubkey
//! hash via instance column. The Mollusk run here goes through the
//! existing 1-tx VERIFY path with the full GLDN0001 payload (which
//! includes the public_inputs suffix the program already supports).

use mollusk_svm::{Mollusk, result::ProgramResult};
use solana_program::{
    instruction::Instruction,
    pubkey::Pubkey,
};
use std::path::PathBuf;

const PROGRAM_NAME: &str = "halo2_solana_verifier_program";

fn load_brc_golden() -> (Vec<u8>, Vec<u8>, [u8; 64], [u8; 128], [u8; 128], Vec<[u8; 32]>) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../circuits/bound-range-check/tests/golden_v2_brc.bin");
    let buf = std::fs::read(&path).unwrap_or_else(|_| panic!(
        "missing {path:?} — run \
         `cargo run -p bound-range-check-circuit --bin gen-brc-proof -- --write-golden` first"
    ));
    let mut cur = 0;
    assert_eq!(&buf[cur..cur + 8], b"GLDN0002");
    cur += 8;
    let vk_len = u32::from_le_bytes([buf[cur], buf[cur+1], buf[cur+2], buf[cur+3]]) as usize;
    cur += 4;
    let vk = buf[cur..cur + vk_len].to_vec();
    cur += vk_len;
    let proof_len = u32::from_le_bytes([buf[cur], buf[cur+1], buf[cur+2], buf[cur+3]]) as usize;
    cur += 4;
    let proof = buf[cur..cur + proof_len].to_vec();
    cur += proof_len;
    let mut g1_one = [0u8; 64]; g1_one.copy_from_slice(&buf[cur..cur + 64]);    cur += 64;
    let mut g2_one = [0u8; 128]; g2_one.copy_from_slice(&buf[cur..cur + 128]);  cur += 128;
    let mut g2_tau = [0u8; 128]; g2_tau.copy_from_slice(&buf[cur..cur + 128]);  cur += 128;
    let n_pi = u32::from_le_bytes([buf[cur], buf[cur+1], buf[cur+2], buf[cur+3]]) as usize;
    cur += 4;
    let mut pis = Vec::with_capacity(n_pi);
    for _ in 0..n_pi {
        let mut pi = [0u8; 32]; pi.copy_from_slice(&buf[cur..cur + 32]);
        pis.push(pi); cur += 32;
    }
    assert_eq!(cur, buf.len());
    (vk, proof, g1_one, g2_one, g2_tau, pis)
}

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
    out.extend_from_slice(&(pis.len() as u32).to_le_bytes());
    for pi in pis { out.extend_from_slice(pi); }
    out
}

#[test]
fn bound_range_check_verify_inside_bpf_vm() {
    let (vk, proof, g1_one, g2_one, g2_tau, pis) = load_brc_golden();
    let instruction_data = build_legacy_payload(&vk, &proof, &g1_one, &g2_one, &g2_tau, &pis);

    let program_id = Pubkey::new_unique();
    let mut mollusk = Mollusk::new(&program_id, PROGRAM_NAME);
    mollusk.compute_budget.compute_unit_limit = 1_000_000_000;
    mollusk.compute_budget.heap_size = 256 * 1024;

    let instruction = Instruction::new_with_bytes(program_id, &instruction_data, vec![]);
    let result = mollusk.process_instruction(&instruction, &[]);
    eprintln!("[brc] program_result        = {:?}", result.program_result);
    eprintln!("[brc] compute_units_consumed = {}", result.compute_units_consumed);

    match result.program_result {
        ProgramResult::Success => eprintln!("[brc] ✓ bound-range-check verifier passed inside BPF VM"),
        other => panic!("bound-range-check BPF run failed: {other:?}"),
    }
}
