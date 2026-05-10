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

fn main() -> Result<()> {
    let program_id: Pubkey = PROGRAM_ID_STR.parse()?;

    // Load golden vector.
    let mut golden = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    golden.push("../../circuits/standard-plonk/tests/golden_v1.bin");
    let payload = std::fs::read(&golden)?;
    let payload_len = payload.len();
    eprintln!("[1/?] loaded golden vector: {payload_len} B from {golden:?}");

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

    // ── final tx: verify ──
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
            eprintln!("This tx will show as `Failed` in the explorer with the");
            eprintln!("`exceeded CUs meter` log — concrete evidence that Halo2");
            eprintln!("verify hits Solana's per-tx CU ceiling. Primary case for");
            eprintln!("the alt_bn128_g1_msm SIMD proposal.");
        }
        Err(e) => {
            eprintln!("    submit FAILED: {e:#}");
        }
    }

    Ok(())
}
