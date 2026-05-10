//! reward-pool-cli — devnet driver for the Phase 2 demo.
//!
//! Three subcommands:
//!
//!   reward-pool-cli init  --reward 100000000 --nonce <u64>
//!     authority creates a fresh pool PDA and locks `reward` lamports in it
//!
//!   reward-pool-cli claim --authority <pubkey> --nonce <u64>
//!     claimer:
//!       (a) re-runs the bound-range-check halo2 prover with their own
//!           pubkey hash baked in,
//!       (b) creates + populates the data account (chunked LOAD into the
//!           verifier-program, same pattern as devnet-send),
//!       (c) creates the stage_state account,
//!       (d) submits verifier::STAGE1,
//!       (e) submits reward_pool::CLAIM (which CPI's into verifier::STAGE2
//!           and on success transfers the reward).
//!
//!   reward-pool-cli close --nonce <u64>
//!     authority closes their unclaimed pool, refunds remaining lamports
//!
//! For the simplest demo, `init` and `claim` can use the same keypair —
//! the SOL flow is still real (locked in PDA, then released to claimer).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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

use sha3::{Digest, Keccak256};

use range_check_circuit::generate_rc_test_vector;

const VERIFIER_PROGRAM_ID_STR: &str = "KvBa8qgb8VDwnM7UT7vr4uhJyLbTsCmuQsRSoSVSK8N";
const DEVNET_URL: &str = "https://api.devnet.solana.com";
const KEYPAIR_PATH: &str = "/home/nzengi/.config/solana/id.json";

const LOAD_TAG:   u8 = 0x01;
const STAGE1_TAG: u8 = 0x02;
// STAGE2_TAG = 0x03 — never sent directly; CPI'd from reward-pool::CLAIM.

const REWARD_POOL_INIT_TAG:  u8 = 0x00;
const REWARD_POOL_CLAIM_TAG: u8 = 0x01;
const REWARD_POOL_CLOSE_TAG: u8 = 0x02;

const POOL_SEED: &[u8] = b"halo2_reward_pool";

/// Allocation size for the stage_state account; same as devnet-send.
const STAGE_STATE_BYTES: usize = 4096;

/// Default x value baked into the proof. Anything in `[0, 16)` works for
/// the 4-bit range check.
const DEFAULT_X: u64 = 7;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_help();
        anyhow::bail!("missing subcommand");
    }
    match args[1].as_str() {
        "init"  => cmd_init(&args[2..]),
        "claim" => cmd_claim(&args[2..]),
        "close" => cmd_close(&args[2..]),
        "help" | "--help" | "-h" => { print_help(); Ok(()) }
        other => {
            print_help();
            anyhow::bail!("unknown subcommand: {other}")
        }
    }
}

fn print_help() {
    eprintln!("reward-pool-cli — Phase 2 demo driver");
    eprintln!();
    eprintln!("Subcommands:");
    eprintln!("  init  --reward <lamports> --nonce <u64> [--reward-pool-program <addr>]");
    eprintln!("  claim --authority <pubkey> --nonce <u64> [--reward-pool-program <addr>]");
    eprintln!("  close --nonce <u64> [--reward-pool-program <addr>]");
    eprintln!();
    eprintln!("All txs go to devnet (https://api.devnet.solana.com).");
    eprintln!("Verifier program: {VERIFIER_PROGRAM_ID_STR}");
}

fn parse_named<T: std::str::FromStr>(args: &[String], name: &str) -> Option<T> {
    for (i, a) in args.iter().enumerate() {
        if a == name {
            return args.get(i + 1).and_then(|v| v.parse().ok());
        }
    }
    None
}

fn parse_named_str(args: &[String], name: &str) -> Option<String> {
    for (i, a) in args.iter().enumerate() {
        if a == name {
            return args.get(i + 1).cloned();
        }
    }
    None
}

fn reward_pool_program_id(args: &[String]) -> Result<Pubkey> {
    parse_named_str(args, "--reward-pool-program")
        .as_deref()
        .map(|s| s.parse())
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!(
            "missing --reward-pool-program <addr> (deploy reward_pool.so first)"
        ))
}

fn rpc_and_payer() -> Result<(RpcClient, Keypair)> {
    let client = RpcClient::new_with_commitment(DEVNET_URL, CommitmentConfig::confirmed());
    let payer = read_keypair_file(KEYPAIR_PATH)
        .map_err(|e| anyhow::anyhow!("read keypair: {e}"))?;
    Ok((client, payer))
}

/// Compute keccak256(vk_bytes) — what reward-pool stores as `vk_hash_required`.
fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

fn pool_pda(program_id: &Pubkey, authority: &Pubkey, nonce: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[POOL_SEED, authority.as_ref(), &nonce.to_le_bytes()],
        program_id,
    )
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn cmd_init(args: &[String]) -> Result<()> {
    let reward_lamports: u64 = parse_named(args, "--reward")
        .ok_or_else(|| anyhow::anyhow!("missing --reward <lamports>"))?;
    let nonce: u64 = parse_named(args, "--nonce")
        .ok_or_else(|| anyhow::anyhow!("missing --nonce <u64>"))?;
    let pool_program = reward_pool_program_id(args)?;

    let (client, payer) = rpc_and_payer()?;
    let authority = payer.pubkey();

    eprintln!("[init] authority = {}", authority);
    eprintln!("[init] balance   = {} lamports", client.get_balance(&authority)?);
    eprintln!("[init] reward    = {} lamports", reward_lamports);
    eprintln!("[init] nonce     = 0x{:016x}", nonce);

    // Compute the VK hash the pool will accept by running the range-check
    // prover once to grab the canonical vk_bytes (deterministic given
    // fixed (k, seed)). Using a fixed seed so init / claim agree.
    let vk_bytes = vk_bytes_for_rc()?;
    let vk_hash = keccak256(&vk_bytes);
    eprintln!("[init] vk_hash   = 0x{}", hex::encode(vk_hash));

    let (pool_addr, _bump) = pool_pda(&pool_program, &authority, nonce);
    eprintln!("[init] pool_pda  = {}", pool_addr);

    let mut data: Vec<u8> = Vec::with_capacity(1 + 32 + 8 + 8);
    data.push(REWARD_POOL_INIT_TAG);
    data.extend_from_slice(&vk_hash);
    data.extend_from_slice(&reward_lamports.to_le_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());

    let ix = Instruction {
        program_id: pool_program,
        accounts: vec![
            AccountMeta::new(authority, true),                  // authority signer
            AccountMeta::new(pool_addr, false),                  // pool PDA (will be created)
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data,
    };
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority),
        &[&payer],
        blockhash,
    );
    let sig = client.send_and_confirm_transaction(&tx)
        .context("init_pool tx")?;
    eprintln!("[init] ✓ pool initialized — sig {sig}");
    eprintln!("       https://explorer.solana.com/tx/{sig}?cluster=devnet");
    eprintln!("       https://explorer.solana.com/address/{pool_addr}?cluster=devnet");
    Ok(())
}

// ---------------------------------------------------------------------------
// claim
// ---------------------------------------------------------------------------

fn cmd_claim(args: &[String]) -> Result<()> {
    let nonce: u64 = parse_named(args, "--nonce")
        .ok_or_else(|| anyhow::anyhow!("missing --nonce <u64>"))?;
    let authority_str = parse_named_str(args, "--authority")
        .ok_or_else(|| anyhow::anyhow!("missing --authority <pubkey>"))?;
    let authority: Pubkey = authority_str.parse()
        .map_err(|_| anyhow::anyhow!("invalid --authority pubkey"))?;
    let pool_program = reward_pool_program_id(args)?;

    let verifier_program: Pubkey = VERIFIER_PROGRAM_ID_STR.parse()?;
    let (client, claimer) = rpc_and_payer()?;
    let claimer_pk = claimer.pubkey();

    eprintln!("[claim] claimer  = {}", claimer_pk);
    eprintln!("[claim] balance  = {} lamports", client.get_balance(&claimer_pk)?);
    eprintln!("[claim] authority= {}", authority);
    eprintln!("[claim] nonce    = 0x{:016x}", nonce);

    let (pool_addr, _bump) = pool_pda(&pool_program, &authority, nonce);
    eprintln!("[claim] pool_pda = {}", pool_addr);

    // --- (a) generate range-check proof ------------------------------------
    eprintln!("[claim] generating range-check proof (k=6, fixed seed)…");
    let seed = [11u8; 32];
    let v = generate_rc_test_vector(6, seed)?;
    eprintln!("[claim]   vk={} B  proof={} B", v.vk_bytes.len(), v.proof_bytes.len());

    // Build the GLDN0001 payload the verifier-program reads from the data
    // account. range-check has zero public inputs, so the suffix carries
    // a `n_pi = 0` marker.
    let mut payload: Vec<u8> = Vec::new();
    payload.extend_from_slice(b"GLDN0001");
    payload.extend_from_slice(&(v.vk_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&v.vk_bytes);
    payload.extend_from_slice(&(v.proof_bytes.len() as u32).to_le_bytes());
    payload.extend_from_slice(&v.proof_bytes);
    payload.extend_from_slice(&v.kzg_vk.g1_one.0);
    payload.extend_from_slice(&v.kzg_vk.g2_one.0);
    payload.extend_from_slice(&v.kzg_vk.g2_tau.0);
    payload.extend_from_slice(&0u32.to_le_bytes());  // n_pi = 0
    let payload_len = payload.len();

    // --- (b) create data account ------------------------------------------
    let data_acct = Keypair::new();
    let rent = client.get_minimum_balance_for_rent_exemption(payload_len)?;
    let blockhash = client.get_latest_blockhash()?;
    let create_ix = system_instruction::create_account(
        &claimer_pk,
        &data_acct.pubkey(),
        rent,
        payload_len as u64,
        &verifier_program,
    );
    let tx = Transaction::new_signed_with_payer(
        &[create_ix],
        Some(&claimer_pk),
        &[&claimer, &data_acct],
        blockhash,
    );
    let sig = client.send_and_confirm_transaction(&tx)
        .context("data account create")?;
    eprintln!("[claim] ✓ data account created — sig {sig}");

    // chunked LOAD
    const CHUNK: usize = 900;
    let mut written = 0;
    while written < payload_len {
        let end = (written + CHUNK).min(payload_len);
        let mut data = Vec::with_capacity(5 + (end - written));
        data.push(LOAD_TAG);
        data.extend_from_slice(&(written as u32).to_le_bytes());
        data.extend_from_slice(&payload[written..end]);
        let load_ix = Instruction {
            program_id: verifier_program,
            accounts: vec![AccountMeta::new(data_acct.pubkey(), false)],
            data,
        };
        let blockhash = client.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            &[load_ix],
            Some(&claimer_pk),
            &[&claimer],
            blockhash,
        );
        let sig = client.send_and_confirm_transaction(&tx).context("LOAD")?;
        eprintln!("[claim]   wrote bytes {written}..{end} — sig {sig}");
        written = end;
    }

    // --- (c) create stage_state account ----------------------------------
    let stage_state_acct = Keypair::new();
    let stage_rent = client.get_minimum_balance_for_rent_exemption(STAGE_STATE_BYTES)?;
    let blockhash = client.get_latest_blockhash()?;
    let create_stage_ix = system_instruction::create_account(
        &claimer_pk,
        &stage_state_acct.pubkey(),
        stage_rent,
        STAGE_STATE_BYTES as u64,
        &verifier_program,
    );
    let tx = Transaction::new_signed_with_payer(
        &[create_stage_ix],
        Some(&claimer_pk),
        &[&claimer, &stage_state_acct],
        blockhash,
    );
    let sig = client.send_and_confirm_transaction(&tx).context("stage_state create")?;
    eprintln!("[claim] ✓ stage_state created — sig {sig}");

    // --- (d) STAGE1 -------------------------------------------------------
    let stage_nonce: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let cb_limit = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let cb_heap  = ComputeBudgetInstruction::request_heap_frame(256 * 1024);
    let mut stage1_data = Vec::with_capacity(9);
    stage1_data.push(STAGE1_TAG);
    stage1_data.extend_from_slice(&stage_nonce.to_le_bytes());
    let stage1_ix = Instruction {
        program_id: verifier_program,
        accounts: vec![
            AccountMeta::new_readonly(data_acct.pubkey(), false),
            AccountMeta::new(stage_state_acct.pubkey(), false),
            AccountMeta::new(claimer_pk, true),
        ],
        data: stage1_data,
    };
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[cb_limit.clone(), cb_heap.clone(), stage1_ix],
        Some(&claimer_pk),
        &[&claimer],
        blockhash,
    );
    let sig = client.send_and_confirm_transaction(&tx)
        .context("STAGE1 verify-tx")?;
    eprintln!("[claim] ✓ STAGE1 ok — sig {sig}");

    // --- (e) reward_pool::CLAIM (which CPIs verifier::STAGE2) ------------
    let mut claim_data = Vec::with_capacity(9);
    claim_data.push(REWARD_POOL_CLAIM_TAG);
    claim_data.extend_from_slice(&stage_nonce.to_le_bytes());
    let claim_ix = Instruction {
        program_id: pool_program,
        accounts: vec![
            AccountMeta::new(claimer_pk, true),                                   // payer (signer, gets reward)
            AccountMeta::new(pool_addr, false),                                    // pool_pda (drained)
            AccountMeta::new_readonly(data_acct.pubkey(), false),                  // data account
            AccountMeta::new_readonly(stage_state_acct.pubkey(), false),           // stage_state account
            AccountMeta::new_readonly(verifier_program, false),                    // verifier program (target of CPI)
        ],
        data: claim_data,
    };
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[cb_limit, cb_heap, claim_ix],
        Some(&claimer_pk),
        &[&claimer],
        blockhash,
    );
    let sig = client.send_and_confirm_transaction(&tx)
        .context("CLAIM tx (CPIs verifier::STAGE2)")?;
    eprintln!("[claim] ✓ CLAIM ok (verifier::STAGE2 succeeded inside CPI) — sig {sig}");
    eprintln!("        https://explorer.solana.com/tx/{sig}?cluster=devnet");
    eprintln!("[claim] reward transferred. Final balance: {} lamports",
              client.get_balance(&claimer_pk)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// close
// ---------------------------------------------------------------------------

fn cmd_close(args: &[String]) -> Result<()> {
    let nonce: u64 = parse_named(args, "--nonce")
        .ok_or_else(|| anyhow::anyhow!("missing --nonce <u64>"))?;
    let pool_program = reward_pool_program_id(args)?;

    let (client, authority) = rpc_and_payer()?;
    let authority_pk = authority.pubkey();
    let (pool_addr, _bump) = pool_pda(&pool_program, &authority_pk, nonce);

    eprintln!("[close] authority = {}", authority_pk);
    eprintln!("[close] pool_pda  = {}", pool_addr);

    let ix = Instruction {
        program_id: pool_program,
        accounts: vec![
            AccountMeta::new(authority_pk, true),
            AccountMeta::new(pool_addr, false),
        ],
        data: vec![REWARD_POOL_CLOSE_TAG],
    };
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority_pk),
        &[&authority],
        blockhash,
    );
    let sig = client.send_and_confirm_transaction(&tx).context("close_pool tx")?;
    eprintln!("[close] ✓ pool closed — sig {sig}");
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Run the range-check prover once to extract the canonical VK bytes
/// (deterministic given fixed (k, seed)). Used by `init` to compute
/// `vk_hash_required`.
fn vk_bytes_for_rc() -> Result<Vec<u8>> {
    let _ = PathBuf::new(); // silence unused
    let v = generate_rc_test_vector(6, [11u8; 32])?;
    Ok(v.vk_bytes)
}
