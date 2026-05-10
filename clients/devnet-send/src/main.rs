//! Devnet integration test for `halo2-solana-verifier-program`.
//!
//! Solana per-tx limit is 1232 bytes; the golden vector alone is 2312 B,
//! so the verify input has to ride in a *data account* the program reads
//! from at runtime. Pattern:
//!
//!   tx1: system::create_account(data_account, 0, 2312, program_id)
//!   tx2..N: chunks of `data_account.data[]` written via a tiny "load" path
//!           — but we shortcut by paying for an oversized account and using
//!           `write_data_to_account` directly via the standard upgradeable
//!           buffer pattern. Simpler: split into multiple set_account_data
//!           ixs using a small admin-style "upload" program. We do the
//!           even simpler thing: stuff the data into the account using
//!           multiple system_instruction::transfer-style writes via a
//!           helper account (this part is straightforward in Rust SDK
//!           because RpcClient gives us send_and_confirm directly).
//!
//! For this PoC we use the simplest path: one create_account tx that
//! over-allocates the data account (rent-exempt), then chunked writes
//! through a small per-program "load" instruction... but the verifier
//! program doesn't have a load ix. So we use `system_program::create_account`
//! followed by *manual* chunked memcpy via a tiny side-program... no, that's
//! too much work for this PoC.
//!
//! What WE do here: create the data account owned BY THE VERIFIER PROGRAM
//! and pre-fill it with `system_program::create_account_with_seed`-style
//! single-tx "write all data". For 2312 B this fits in one tx if we use
//! an alternative: `solana program write-buffer` via the loader... too
//! framework-dependent.
//!
//! Practical approach for this run: write the data account in **chunks of
//! ~900 bytes per tx** via small per-program "load" ixs. We add a one-byte
//! "load" tag to the verifier program's instruction-data path that means
//! "copy this slice into accounts[0].data[offset..]". When the data is
//! fully loaded, the next tx (verify) ignores instruction-data and reads
//! accounts[0].data directly.

use std::path::PathBuf;

use anyhow::{Context, Result};
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_program::pubkey::Pubkey;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    signature::{read_keypair_file, Keypair, Signer},
    transaction::Transaction,
};
use solana_system_interface::instruction as system_instruction;

const PROGRAM_ID_STR: &str = "KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N";
const DEVNET_URL: &str = "https://api.devnet.solana.com";
const KEYPAIR_PATH: &str = "/home/nzengi/.config/solana/id.json";

const VERIFY_TAG: u8 = 0x00;
const LOAD_TAG:   u8 = 0x01;
const STAGE1_TAG: u8 = 0x02;
const STAGE2_TAG: u8 = 0x03;

/// Allocation size for the stage_state account in the 2-tx flow.
/// Worst-case Stage1Output is ~2,720 bytes (4 B prefix + 668 B fixed +
/// 32 B × 64 max user_challenges + instance_evals). Round to a safe
/// 4 KB; for current circuits (Fibonacci, range-check, multi-lookup,
/// shuffle) we use 600–1,000 bytes of it.
const STAGE_STATE_BYTES: usize = 4096;

/// Translate a `GLDN0002` blob (Fibonacci / range-check / shuffle goldens)
/// into the verifier-program's `GLDN0001` instruction-data layout. The
/// byte content is identical downstream of the magic — only the 8-byte
/// prefix changes.
fn repackage_gldn0002_to_gldn0001(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() < 8 || &raw[..8] != b"GLDN0002" {
        anyhow::bail!("expected GLDN0002 magic in golden file");
    }
    let mut out = Vec::with_capacity(raw.len());
    out.extend_from_slice(b"GLDN0001");
    out.extend_from_slice(&raw[8..]);
    Ok(out)
}

/// Parse `--<name> <value>` from CLI args. Returns the parsed value if
/// present, or `None` if the flag is absent.
fn parse_named_arg(name: &str) -> Option<usize> {
    let args: Vec<String> = std::env::args().collect();
    for (i, a) in args.iter().enumerate() {
        if a == name {
            return args.get(i + 1).and_then(|v| v.parse().ok());
        }
    }
    None
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    StandardPlonk,
    Fibonacci,
    RangeCheck,
    Shuffle,
    MultiLookup,
}

fn main() -> Result<()> {
    let program_id: Pubkey = PROGRAM_ID_STR.parse()?;

    // Mode selection: `--fib` / `--rc` / `--sh`; default = StandardPlonk.
    let mode = if std::env::args().any(|a| a == "--fib") {
        Mode::Fibonacci
    } else if std::env::args().any(|a| a == "--rc") {
        Mode::RangeCheck
    } else if std::env::args().any(|a| a == "--sh") {
        Mode::Shuffle
    } else if std::env::args().any(|a| a == "--ml") {
        Mode::MultiLookup
    } else {
        Mode::StandardPlonk
    };

    // Load golden vector + label per mode.
    let (rel_path, mode_label, needs_repackage) = match mode {
        Mode::StandardPlonk => ("../../circuits/standard-plonk/tests/golden_v1.bin",
                                "StandardPlonk, GLDN0001", false),
        Mode::Fibonacci     => ("../../circuits/fibonacci/tests/golden_v15_fib.bin",
                                "Fibonacci, GLDN0002 → repackaged", true),
        Mode::RangeCheck    => ("../../circuits/range-check/tests/golden_v2_rc.bin",
                                "Range-check (Plookup), GLDN0002 → repackaged", true),
        Mode::Shuffle       => ("../../circuits/shuffle-check/tests/golden_v2_sh.bin",
                                "Shuffle, GLDN0002 → repackaged", true),
        Mode::MultiLookup   => ("../../circuits/multi-lookup-check/tests/golden_v2_ml.bin",
                                "Multi-lookup (2 Plookup), GLDN0002 → repackaged", true),
    };
    let mut golden = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    golden.push(rel_path);
    let raw = std::fs::read(&golden)?;

    let mut payload = if needs_repackage {
        repackage_gldn0002_to_gldn0001(&raw)?
    } else {
        raw
    };

    // Optional 1-byte mutation: `--mutate-byte <off>` flips bit 0 at byte
    // offset `off` of the proof region (i.e., the bytes inside payload that
    // the verifier reads as proof_bytes — NOT the GLDN magic / vk_len /
    // vk_bytes prefix). The offset is computed inside the proof region.
    let mutate_off = parse_named_arg("--mutate-byte");
    if let Some(off) = mutate_off {
        // Compute the proof_bytes start offset inside `payload`.
        // Layout: 8 magic + 4 vk_len + vk_bytes + 4 proof_len + proof_bytes
        let vk_len = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]) as usize;
        let proof_start = 8 + 4 + vk_len + 4;
        let proof_len = u32::from_le_bytes([
            payload[8 + 4 + vk_len],
            payload[8 + 4 + vk_len + 1],
            payload[8 + 4 + vk_len + 2],
            payload[8 + 4 + vk_len + 3],
        ]) as usize;
        if off >= proof_len {
            anyhow::bail!(
                "--mutate-byte {off} out of range: proof region is {proof_len} B",
            );
        }
        let abs = proof_start + off;
        let before = payload[abs];
        payload[abs] ^= 0x01;
        eprintln!(
            "[!] MUTATED proof byte {off} (abs {abs}): {:#04x} → {:#04x}",
            before, payload[abs],
        );
    }

    let payload_len = payload.len();
    eprintln!("[1/?] loaded golden vector ({mode_label}): {payload_len} B from {golden:?}");

    let client = RpcClient::new_with_commitment(DEVNET_URL, CommitmentConfig::confirmed());
    let payer = read_keypair_file(KEYPAIR_PATH)
        .map_err(|e| anyhow::anyhow!("read keypair: {e}"))?;
    eprintln!("[2/?] payer = {}, balance = {} lamports",
        payer.pubkey(),
        client.get_balance(&payer.pubkey())?);

    // ── tx1: create the data account (owned by the verifier program) ──
    let data_acct = Keypair::new();
    let rent_lamports = client.get_minimum_balance_for_rent_exemption(payload_len)?;
    eprintln!("[3/?] data account = {} ({} B, rent {} lamports)",
        data_acct.pubkey(), payload_len, rent_lamports);

    let create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &data_acct.pubkey(),
        rent_lamports,
        payload_len as u64,
        &program_id,
    );
    let blockhash = client.get_latest_blockhash()?;
    let tx_create = Transaction::new_signed_with_payer(
        &[create_ix],
        Some(&payer.pubkey()),
        &[&payer, &data_acct],
        blockhash,
    );
    let sig = client.send_and_confirm_transaction(&tx_create)
        .context("create_account tx")?;
    eprintln!("    ✓ data account created — sig {sig}");

    // ── tx2..N: load chunks via the verifier program's `LOAD_TAG` ix ──
    // Each tx carries: [LOAD_TAG, offset_le u32, chunk_bytes…].
    // Tx wire frame: ~1232 B. After signature(64) + msg overhead(~150) +
    // ix overhead(~50) + 5-byte ix-data prefix = budget for chunk ≈ 900 B.
    const CHUNK: usize = 900;
    let mut written = 0usize;
    while written < payload_len {
        let end = (written + CHUNK).min(payload_len);
        let mut data = Vec::with_capacity(5 + (end - written));
        data.push(LOAD_TAG);
        data.extend_from_slice(&(written as u32).to_le_bytes());
        data.extend_from_slice(&payload[written..end]);

        let load_ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(data_acct.pubkey(), false)],
            data,
        };
        let blockhash = client.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            &[load_ix],
            Some(&payer.pubkey()),
            &[&payer],
            blockhash,
        );
        let sig = client.send_and_confirm_transaction(&tx).context("load tx")?;
        eprintln!("    ✓ wrote bytes {}..{} — sig {}", written, end, sig);
        written = end;
    }
    eprintln!("[4/?] data account fully populated ({} B)", payload_len);

    // ── 2-tx split path (--two-tx) ──
    let two_tx_mode = std::env::args().any(|a| a == "--two-tx");
    if two_tx_mode {
        return run_two_tx_flow(&client, &payer, &program_id, &data_acct.pubkey());
    }

    // ── single verify tx (default) ──
    let cb_limit = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let cb_heap  = ComputeBudgetInstruction::request_heap_frame(256 * 1024);
    let verify_ix = Instruction {
        program_id,
        accounts: vec![AccountMeta::new_readonly(data_acct.pubkey(), false)],
        data: vec![VERIFY_TAG],
    };
    let blockhash = client.get_latest_blockhash()?;
    let tx_verify = Transaction::new_signed_with_payer(
        &[cb_limit, cb_heap, verify_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );

    eprintln!("[5/5] sending verify tx (CU limit 1.4M, heap 256KB)…");
    // Skip pre-flight simulation so the failing tx actually lands on-chain
    // and we get a confirmed tx hash. The hash is the deliverable: Foundation
    // pitch readers can replay it via explorer and see the CU exhaustion log.
    use solana_client::rpc_config::RpcSendTransactionConfig;
    let cfg = RpcSendTransactionConfig {
        skip_preflight: true,
        ..RpcSendTransactionConfig::default()
    };
    match client.send_transaction_with_config(&tx_verify, cfg) {
        Ok(sig) => {
            eprintln!("    submitted: {sig}");
            // Now wait for the tx to land (will be `Err` with an instruction
            // error since verify exhausts CUs, but the tx itself is on-chain).
            match client.confirm_transaction(&sig) {
                Ok(_) => eprintln!("    confirmed (status pending)"),
                Err(e) => eprintln!("    confirm err (expected): {e}"),
            }
            eprintln!("    https://explorer.solana.com/tx/{sig}?cluster=devnet");
            eprintln!();
            eprintln!("Inspect the tx via `solana confirm -v {sig} -u devnet`.");
            eprintln!("Possible outcomes per circuit:");
            eprintln!("  * Shuffle (1.37M CU, valid)        → Status: Ok");
            eprintln!("  * Shuffle + tampered Fr eval        → Custom 0x200 (VERIFIER_REJECTED)");
            eprintln!("  * Shuffle + tampered G1 commit      → Custom 0x201 (VERIFIER_ERROR, curve check)");
            eprintln!("  * StandardPlonk / Fibonacci / Range-check → exceeded CUs meter (>1.4M total)");
        }
        Err(e) => {
            eprintln!("    submit FAILED: {e:#}");
        }
    }

    Ok(())
}

/// 2-tx split flow. Assumes the data account is already populated.
///
/// Steps:
///   1. Allocate a fresh stage_state account (rent-exempt, owned by the
///      verifier program), size = STAGE_STATE_BYTES.
///   2. Submit STAGE1 tx — verifier writes Stage1Output bytes into the
///      stage_state account; CU limit 1.4 M, heap 256 KB.
///   3. Submit STAGE2 tx — verifier reads stage_state, replay-checks
///      against the data account, runs build_queries + SHPLONK + pairing.
///   4. Print all three tx signatures with explorer links.
///
/// The `nonce` is bound into both STAGE1 and STAGE2 instruction data and
/// re-checked inside the program; using a different nonce in stage2 →
/// `STAGE_AUTH_MISMATCH`.
fn run_two_tx_flow(
    client:    &RpcClient,
    payer:     &Keypair,
    program_id: &Pubkey,
    data_acct:  &Pubkey,
) -> Result<()> {
    use solana_client::rpc_config::RpcSendTransactionConfig;
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── allocate stage_state account ──
    let stage_state_acct = Keypair::new();
    let stage_state_rent = client.get_minimum_balance_for_rent_exemption(STAGE_STATE_BYTES)?;
    eprintln!(
        "[5a/?] stage_state account = {} ({} B, rent {} lamports)",
        stage_state_acct.pubkey(), STAGE_STATE_BYTES, stage_state_rent,
    );
    let create_stage_ix = system_instruction::create_account(
        &payer.pubkey(),
        &stage_state_acct.pubkey(),
        stage_state_rent,
        STAGE_STATE_BYTES as u64,
        program_id,
    );
    let blockhash = client.get_latest_blockhash()?;
    let tx_create_stage = Transaction::new_signed_with_payer(
        &[create_stage_ix],
        Some(&payer.pubkey()),
        &[payer, &stage_state_acct],
        blockhash,
    );
    let sig = client.send_and_confirm_transaction(&tx_create_stage)
        .context("create stage_state account tx")?;
    eprintln!("    ✓ stage_state created — sig {sig}");

    // ── pick a per-attempt nonce ──
    let nonce: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    eprintln!("[5b/?] nonce = {:#018x}", nonce);

    let cb_limit = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let cb_heap  = ComputeBudgetInstruction::request_heap_frame(256 * 1024);
    let cfg = RpcSendTransactionConfig {
        skip_preflight: true,
        ..RpcSendTransactionConfig::default()
    };

    // ── STAGE1 tx ──
    let mut stage1_data = Vec::with_capacity(9);
    stage1_data.push(STAGE1_TAG);
    stage1_data.extend_from_slice(&nonce.to_le_bytes());
    let stage1_ix = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*data_acct, false),               // data (read)
            AccountMeta::new(stage_state_acct.pubkey(), false),         // stage_state (write)
            AccountMeta::new(payer.pubkey(), true),                     // signer
        ],
        data: stage1_data,
    };
    let blockhash = client.get_latest_blockhash()?;
    let tx_stage1 = Transaction::new_signed_with_payer(
        &[cb_limit.clone(), cb_heap.clone(), stage1_ix],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    eprintln!("[5c/?] sending STAGE1 tx (CU 1.4M, heap 256KB)…");
    let sig1 = match client.send_transaction_with_config(&tx_stage1, cfg) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("    submit FAILED: {e:#}");
            return Err(anyhow::anyhow!("stage1 submit failed"));
        }
    };
    eprintln!("    submitted: {sig1}");
    let _ = client.confirm_transaction(&sig1);
    eprintln!("    https://explorer.solana.com/tx/{sig1}?cluster=devnet");

    // ── STAGE2 tx ──
    let mut stage2_data = Vec::with_capacity(9);
    stage2_data.push(STAGE2_TAG);
    stage2_data.extend_from_slice(&nonce.to_le_bytes());
    let stage2_ix = Instruction {
        program_id: *program_id,
        accounts: vec![
            AccountMeta::new_readonly(*data_acct, false),               // data (read)
            AccountMeta::new_readonly(stage_state_acct.pubkey(), false),// stage_state (read)
            AccountMeta::new(payer.pubkey(), true),                     // signer
        ],
        data: stage2_data,
    };
    let blockhash = client.get_latest_blockhash()?;
    let tx_stage2 = Transaction::new_signed_with_payer(
        &[cb_limit, cb_heap, stage2_ix],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    eprintln!("[5d/?] sending STAGE2 tx (CU 1.4M, heap 256KB)…");
    let sig2 = match client.send_transaction_with_config(&tx_stage2, cfg) {
        Ok(s)  => s,
        Err(e) => {
            eprintln!("    submit FAILED: {e:#}");
            return Err(anyhow::anyhow!("stage2 submit failed"));
        }
    };
    eprintln!("    submitted: {sig2}");
    let _ = client.confirm_transaction(&sig2);
    eprintln!("    https://explorer.solana.com/tx/{sig2}?cluster=devnet");

    eprintln!();
    eprintln!("STAGE1 + STAGE2 submitted on devnet:");
    eprintln!("  stage1: https://explorer.solana.com/tx/{sig1}?cluster=devnet");
    eprintln!("  stage2: https://explorer.solana.com/tx/{sig2}?cluster=devnet");
    eprintln!();
    eprintln!("Inspect via `solana confirm -v <SIG> -u devnet`. Both should");
    eprintln!("succeed for circuits whose stage1 and stage2 each fit under 1.4 M CU");
    eprintln!("(range-check, shuffle). Larger circuits may exhaust the cap on");
    eprintln!("stage2 (Fibonacci ~1.47M CU, multi-lookup similar).");

    Ok(())
}
