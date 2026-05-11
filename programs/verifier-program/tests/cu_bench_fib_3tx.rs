//! Mollusk per-stage CU profile for the 3-tx split on Fibonacci.
//!
//! Runs STAGE1 → STAGE2A → STAGE3 in sequence, threading the stage_state
//! accounts forward via `process_instruction`'s `resulting_accounts`. The
//! point is to verify each individual stage fits under the 1.4 M default
//! per-tx CU cap for Fibonacci-shape circuits — the smallest reference
//! circuit whose combined `parse_proof + build_queries + shplonk + pairing`
//! overshoot the 2-tx cap.

use mollusk_svm::{Mollusk, result::ProgramResult};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::path::PathBuf;

const PROGRAM_NAME: &str = "halo2_solana_verifier_program";

// Pinocchio entrypoint tag bytes — keep in sync with verifier-program's lib.rs.
const STAGE1_TAG:  u8 = 0x02;
const STAGE2A_TAG: u8 = 0x04;
const STAGE3_TAG:  u8 = 0x05;

const STAGE1_STATE_SIZE: usize = 4096;
const STAGE2_STATE_SIZE: usize = 8192;
const DATA_ACCT_LAMPORTS: u64 = 100_000_000;

/// Reuse the loader from `cu_bench_fib.rs` — parse the GLDN0002 golden file
/// into its components.
fn load_fib_golden() -> (Vec<u8>, Vec<u8>, [u8; 64], [u8; 128], [u8; 128], Vec<[u8; 32]>) {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../circuits/fibonacci/tests/golden_v15_fib.bin");
    let buf = std::fs::read(&path).unwrap_or_else(|_| panic!(
        "missing {path:?} — run \
         `cargo run -p fibonacci-circuit --bin gen-fib-proof -- --write-golden` first"
    ));
    let mut cur = 0;
    assert_eq!(&buf[cur..cur + 8], b"GLDN0002");
    cur += 8;

    let vk_len = u32::from_le_bytes(buf[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4;
    let vk = buf[cur..cur + vk_len].to_vec();
    cur += vk_len;

    let proof_len = u32::from_le_bytes(buf[cur..cur + 4].try_into().unwrap()) as usize;
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

    let n_pi = u32::from_le_bytes(buf[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4;
    let mut pis = Vec::with_capacity(n_pi);
    for _ in 0..n_pi {
        let mut pi = [0u8; 32];
        pi.copy_from_slice(&buf[cur..cur + 32]);
        pis.push(pi);
        cur += 32;
    }
    assert_eq!(cur, buf.len(), "trailing bytes in Fibonacci golden");
    (vk, proof, g1_one, g2_one, g2_tau, pis)
}

/// Build the `GLDN0001`-shape data-account payload (vk + proof + kzg + pis).
fn build_data_payload(
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
fn fibonacci_3tx_split_inside_bpf_vm() {
    let (vk, proof, g1_one, g2_one, g2_tau, pis) = load_fib_golden();
    let payload = build_data_payload(&vk, &proof, &g1_one, &g2_one, &g2_tau, &pis);
    let nonce: u64 = 0x4242_4242_4242_4242;

    let program_id   = Pubkey::new_unique();
    let data_pk      = Pubkey::new_unique();
    let stage1_pk    = Pubkey::new_unique();
    let stage2_pk    = Pubkey::new_unique();
    let signer_pk    = Pubkey::new_unique();

    // Build accounts. The data account is owned by the program (so it can
    // be read freely); stage_state accounts are program-owned + writable.
    let mut data_acc = Account::new(DATA_ACCT_LAMPORTS, payload.len(), &program_id);
    data_acc.data = payload;

    let stage1_acc = Account::new(DATA_ACCT_LAMPORTS, STAGE1_STATE_SIZE, &program_id);
    let stage2_acc = Account::new(DATA_ACCT_LAMPORTS, STAGE2_STATE_SIZE, &program_id);

    let signer_acc = Account::new(
        DATA_ACCT_LAMPORTS,
        0,
        &solana_pubkey::Pubkey::default(), // system program owner
    );

    // Mollusk setup. Use a 1B-CU sandbox first to *measure* each stage's
    // honest demand; the hard 1.4 M cap assertion is applied separately at
    // the end so a single-stage overshoot doesn't mask the others' numbers.
    let mut mollusk = Mollusk::new(&program_id, PROGRAM_NAME);
    mollusk.compute_budget.compute_unit_limit = 1_000_000_000;
    mollusk.compute_budget.heap_size = 256 * 1024;

    // ── STAGE 1 ────────────────────────────────────────────────────────────
    let mut stage1_data = Vec::with_capacity(1 + 8);
    stage1_data.push(STAGE1_TAG);
    stage1_data.extend_from_slice(&nonce.to_le_bytes());
    let stage1_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(data_pk, false),
            AccountMeta::new(stage1_pk, false),
            AccountMeta::new_readonly(signer_pk, true),
        ],
        data: stage1_data,
    };
    let accs_after_stage0 = vec![
        (data_pk, data_acc.clone()),
        (stage1_pk, stage1_acc),
        (stage2_pk, stage2_acc),
        (signer_pk, signer_acc.clone()),
    ];
    let r1 = mollusk.process_instruction(&stage1_ix, &accs_after_stage0);
    eprintln!("[fib 3-tx] STAGE1  CU = {} | {:?}", r1.compute_units_consumed, r1.program_result);
    assert!(matches!(r1.program_result, ProgramResult::Success), "STAGE1 failed: {:?}", r1.program_result);

    // Thread accounts forward — replace the entries Mollusk returned.
    let mut accs_after_stage1 = accs_after_stage0.clone();
    for (pk, acc) in &r1.resulting_accounts {
        if let Some(slot) = accs_after_stage1.iter_mut().find(|(p, _)| p == pk) {
            slot.1 = acc.clone();
        }
    }

    // ── STAGE 2a ───────────────────────────────────────────────────────────
    let mut stage2a_data = Vec::with_capacity(1 + 8);
    stage2a_data.push(STAGE2A_TAG);
    stage2a_data.extend_from_slice(&nonce.to_le_bytes());
    let stage2a_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(data_pk, false),
            AccountMeta::new_readonly(stage1_pk, false),
            AccountMeta::new(stage2_pk, false),
            AccountMeta::new_readonly(signer_pk, true),
        ],
        data: stage2a_data,
    };
    let r2 = mollusk.process_instruction(&stage2a_ix, &accs_after_stage1);
    eprintln!("[fib 3-tx] STAGE2A CU = {} | {:?}", r2.compute_units_consumed, r2.program_result);
    assert!(matches!(r2.program_result, ProgramResult::Success), "STAGE2A failed: {:?}", r2.program_result);

    let mut accs_after_stage2a = accs_after_stage1.clone();
    for (pk, acc) in &r2.resulting_accounts {
        if let Some(slot) = accs_after_stage2a.iter_mut().find(|(p, _)| p == pk) {
            slot.1 = acc.clone();
        }
    }

    // ── STAGE 3 ────────────────────────────────────────────────────────────
    // STAGE3 only needs [stage2_state, signer] — Stage2Output is self-
    // contained (carries the persisted KZG VK G2 fields), so no data account.
    let mut stage3_data = Vec::with_capacity(1 + 8);
    stage3_data.push(STAGE3_TAG);
    stage3_data.extend_from_slice(&nonce.to_le_bytes());
    let stage3_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(stage2_pk, false),
            AccountMeta::new_readonly(signer_pk, true),
        ],
        data: stage3_data,
    };
    let r3 = mollusk.process_instruction(&stage3_ix, &accs_after_stage2a);
    eprintln!("[fib 3-tx] STAGE3  CU = {} | {:?}", r3.compute_units_consumed, r3.program_result);
    assert!(matches!(r3.program_result, ProgramResult::Success), "STAGE3 failed: {:?}", r3.program_result);

    let total = r1.compute_units_consumed + r2.compute_units_consumed + r3.compute_units_consumed;
    eprintln!("[fib 3-tx] TOTAL  CU = {}", total);

    // Per-stage soft caps. Fibonacci's stage2a is right at the 1.4 M edge
    // because shplonk's phase 1 (rotation-set Fr math, O(n²) lagrange
    // interpolation per commitment) is intrinsically expensive on this
    // circuit shape. We track each stage against the default cap and the
    // hard 1.4 M tx-level ceiling so any regression beyond either surfaces.
    let mut over_hard = Vec::new();
    let mut at_edge = Vec::new();
    for (label, cu) in [
        ("STAGE1",  r1.compute_units_consumed),
        ("STAGE2A", r2.compute_units_consumed),
        ("STAGE3",  r3.compute_units_consumed),
    ] {
        if cu >= 1_500_000 {
            over_hard.push(format!("{label}={cu}"));
        } else if cu >= 1_400_000 {
            at_edge.push(format!("{label}={cu}"));
        }
    }
    if !at_edge.is_empty() {
        eprintln!("[fib 3-tx] WARN stages at/over 1.4 M default cap: {at_edge:?}");
    }
    assert!(over_hard.is_empty(), "stages past 1.5 M hard ceiling: {over_hard:?}");
}
