//! Mollusk per-stage CU profile for the 3-tx split across every available
//! reference circuit. One test per circuit reports STAGE1/STAGE2A/STAGE3 CU
//! and asserts each stage fits under Solana's 1.4 M default per-tx cap.
//!
//! The 1-tx Fibonacci 3-tx benchmark in `cu_bench_fib_3tx.rs` stays as-is
//! (warning-not-failing on edge cases); this file is the harder cap-check.

use mollusk_svm::{Mollusk, result::ProgramResult};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::path::PathBuf;

const PROGRAM_NAME: &str = "halo2_solana_verifier_program";
const STAGE1_TAG:  u8 = 0x02;
const STAGE2A_TAG: u8 = 0x04;
const STAGE3_TAG:  u8 = 0x05;
const STAGE1_STATE_SIZE: usize = 4096;
const STAGE2_STATE_SIZE: usize = 8192;
const ACCT_LAMPORTS: u64 = 100_000_000;
const PER_STAGE_CAP: u64 = 1_400_000;

/// Format of every "GLDN0002"-style golden produced by our `gen-*-proof`
/// circuits. Returns a flat GLDN0001 payload for the program's data
/// account (vk + proof + kzg + pi suffix).
fn load_v2_golden_to_v1_payload(rel: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    let buf = std::fs::read(&path).unwrap_or_else(|_| panic!("missing {path:?}"));

    let mut cur = 0;
    assert_eq!(&buf[cur..cur + 8], b"GLDN0002", "bad golden magic in {rel}");
    cur += 8;

    let vk_len = u32::from_le_bytes(buf[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4;
    let vk = &buf[cur..cur + vk_len];
    cur += vk_len;

    let proof_len = u32::from_le_bytes(buf[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4;
    let proof = &buf[cur..cur + proof_len];
    cur += proof_len;

    let g1_one = &buf[cur..cur + 64];   cur += 64;
    let g2_one = &buf[cur..cur + 128];  cur += 128;
    let g2_tau = &buf[cur..cur + 128];  cur += 128;

    let n_pi = u32::from_le_bytes(buf[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4;
    let pi_region = &buf[cur..cur + n_pi * 32];
    cur += n_pi * 32;
    assert_eq!(cur, buf.len(), "trailing bytes in {rel}");

    let mut out = Vec::with_capacity(buf.len());
    out.extend_from_slice(b"GLDN0001");
    out.extend_from_slice(&(vk.len() as u32).to_le_bytes());
    out.extend_from_slice(vk);
    out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    out.extend_from_slice(proof);
    out.extend_from_slice(g1_one);
    out.extend_from_slice(g2_one);
    out.extend_from_slice(g2_tau);
    out.extend_from_slice(&(n_pi as u32).to_le_bytes());
    out.extend_from_slice(pi_region);
    out
}

/// StandardPlonk's golden is already in GLDN0001 form (no PI suffix).
fn load_v1_golden_passthrough(rel: &str) -> Vec<u8> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|_| panic!("missing {path:?}"))
}

/// Run the 3-tx flow under Mollusk for the given GLDN0001 data payload.
/// Asserts each stage fits under `PER_STAGE_CAP`. Returns `(stage1, stage2a, stage3)`.
fn run_3tx(label: &str, payload: Vec<u8>) -> (u64, u64, u64) {
    let nonce: u64 = 0xDEAD_BEEF_CAFE_0001;
    let program_id = Pubkey::new_unique();
    let data_pk    = Pubkey::new_unique();
    let stage1_pk  = Pubkey::new_unique();
    let stage2_pk  = Pubkey::new_unique();
    let signer_pk  = Pubkey::new_unique();

    let mut data_acc = Account::new(ACCT_LAMPORTS, payload.len(), &program_id);
    data_acc.data = payload;
    let stage1_acc = Account::new(ACCT_LAMPORTS, STAGE1_STATE_SIZE, &program_id);
    let stage2_acc = Account::new(ACCT_LAMPORTS, STAGE2_STATE_SIZE, &program_id);
    let signer_acc = Account::new(ACCT_LAMPORTS, 0, &Pubkey::default());

    let mut mollusk = Mollusk::new(&program_id, PROGRAM_NAME);
    // Use a generous CU sandbox so an individual stage's overshoot still
    // produces a measurement (we cap-check after, not inside the VM).
    mollusk.compute_budget.compute_unit_limit = 1_000_000_000;
    mollusk.compute_budget.heap_size = 256 * 1024;

    // STAGE1: [data RO, stage1_state RW, signer]
    let stage1_data = [&[STAGE1_TAG][..], &nonce.to_le_bytes()].concat();
    let stage1_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(data_pk, false),
            AccountMeta::new(stage1_pk, false),
            AccountMeta::new_readonly(signer_pk, true),
        ],
        data: stage1_data,
    };
    let accs0 = vec![
        (data_pk, data_acc.clone()),
        (stage1_pk, stage1_acc),
        (stage2_pk, stage2_acc),
        (signer_pk, signer_acc.clone()),
    ];
    let r1 = mollusk.process_instruction(&stage1_ix, &accs0);
    eprintln!("[{label} 3-tx] STAGE1  CU = {} | {:?}", r1.compute_units_consumed, r1.program_result);
    assert!(matches!(r1.program_result, ProgramResult::Success), "STAGE1: {:?}", r1.program_result);

    let mut accs1 = accs0.clone();
    for (pk, a) in &r1.resulting_accounts {
        if let Some(slot) = accs1.iter_mut().find(|(p, _)| p == pk) { slot.1 = a.clone(); }
    }

    // STAGE2A: [data RO, stage1_state RO, stage2_state RW, signer]
    let stage2a_data = [&[STAGE2A_TAG][..], &nonce.to_le_bytes()].concat();
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
    let r2 = mollusk.process_instruction(&stage2a_ix, &accs1);
    eprintln!("[{label} 3-tx] STAGE2A CU = {} | {:?}", r2.compute_units_consumed, r2.program_result);
    assert!(matches!(r2.program_result, ProgramResult::Success), "STAGE2A: {:?}", r2.program_result);

    let mut accs2 = accs1.clone();
    for (pk, a) in &r2.resulting_accounts {
        if let Some(slot) = accs2.iter_mut().find(|(p, _)| p == pk) { slot.1 = a.clone(); }
    }

    // STAGE3: [stage2_state RO, signer]
    let stage3_data = [&[STAGE3_TAG][..], &nonce.to_le_bytes()].concat();
    let stage3_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new_readonly(stage2_pk, false),
            AccountMeta::new_readonly(signer_pk, true),
        ],
        data: stage3_data,
    };
    let r3 = mollusk.process_instruction(&stage3_ix, &accs2);
    eprintln!("[{label} 3-tx] STAGE3  CU = {} | {:?}", r3.compute_units_consumed, r3.program_result);
    assert!(matches!(r3.program_result, ProgramResult::Success), "STAGE3: {:?}", r3.program_result);

    let total = r1.compute_units_consumed + r2.compute_units_consumed + r3.compute_units_consumed;
    eprintln!("[{label} 3-tx] TOTAL   CU = {total}");

    // Hard cap assertion: every stage must fit under 1.4 M.
    for (name, cu) in [
        ("STAGE1",  r1.compute_units_consumed),
        ("STAGE2A", r2.compute_units_consumed),
        ("STAGE3",  r3.compute_units_consumed),
    ] {
        assert!(cu < PER_STAGE_CAP, "{label}/{name} exceeded 1.4 M cap: {cu}");
    }

    (
        r1.compute_units_consumed,
        r2.compute_units_consumed,
        r3.compute_units_consumed,
    )
}

#[test]
fn multi_lookup_3tx_under_cap() {
    let payload = load_v2_golden_to_v1_payload(
        "../../circuits/multi-lookup-check/tests/golden_v2_ml.bin",
    );
    let _ = run_3tx("ml", payload);
}

#[test]
fn bound_range_check_3tx_under_cap() {
    let payload = load_v2_golden_to_v1_payload(
        "../../circuits/bound-range-check/tests/golden_v2_brc.bin",
    );
    let _ = run_3tx("brc", payload);
}

#[test]
fn standard_plonk_3tx_under_cap() {
    let payload = load_v1_golden_passthrough(
        "../../circuits/standard-plonk/tests/golden_v1.bin",
    );
    let _ = run_3tx("sp", payload);
}

#[test]
fn shuffle_3tx_under_cap() {
    let payload = load_v2_golden_to_v1_payload(
        "../../circuits/shuffle-check/tests/golden_v2_sh.bin",
    );
    let _ = run_3tx("sh", payload);
}

#[test]
fn range_check_3tx_under_cap() {
    let payload = load_v2_golden_to_v1_payload(
        "../../circuits/range-check/tests/golden_v2_rc.bin",
    );
    let _ = run_3tx("rc", payload);
}

#[test]
fn fibonacci_3tx_under_cap() {
    let payload = load_v2_golden_to_v1_payload(
        "../../circuits/fibonacci/tests/golden_v15_fib.bin",
    );
    let _ = run_3tx("fib", payload);
}
