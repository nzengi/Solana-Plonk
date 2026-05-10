//! Reward-pool program — ZK-gated SOL escrow.
//!
//! Three instructions wrap a one-shot SOL pool whose payout is gated
//! behind a halo2 proof:
//!
//!   - `init_pool(authority, vk_hash_required, reward_lamports, nonce)`
//!     authority locks `reward_lamports` SOL into a per-(authority, nonce)
//!     PDA owned by this program. Only proofs verifying against the
//!     specific halo2 VK whose `keccak256(vk_bytes) == vk_hash_required`
//!     can claim.
//!
//!   - `claim(payer, pool_pda, data_account, stage_state, verifier_program,
//!     stage2_nonce)` — claimer:
//!         1. CPI's into the verifier-program's STAGE2 with the prepared
//!            stage_state PDA (set up off-chain by running STAGE1 first);
//!         2. on STAGE2 success, transfers `reward_lamports` from pool_pda
//!            to payer;
//!         3. marks the pool `claimed` so subsequent attempts fail-fast.
//!
//!   - `close_pool(authority, pool_pda)` — authority refund of any
//!     remaining lamports. Useful before max_claims is reached.
//!
//! Pool state is stored in the pool_pda's account data using a small
//! hand-rolled byte format (no Borsh dependency to keep this minimal).

extern crate alloc;

use alloc::vec::Vec;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    keccak,
    msg,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
};
use solana_system_interface::instruction as system_instruction;
use solana_system_interface::program as system_program;

#[cfg(feature = "bpf-entrypoint")]
solana_program::entrypoint!(process_instruction);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub mod errors {
    pub const POOL_OUT_OF_BOUNDS:      u32 = 0x500;
    pub const POOL_ALREADY_CLAIMED:    u32 = 0x501;
    pub const POOL_AUTHORITY_MISMATCH: u32 = 0x502;
    pub const VK_HASH_MISMATCH:        u32 = 0x503;
    pub const CLAIMER_HASH_MISMATCH:   u32 = 0x504;
    pub const VERIFIER_FAILED:         u32 = 0x505;
    pub const STAGE_STATE_INVALID:     u32 = 0x506;
    pub const POOL_NOT_OWNED:          u32 = 0x507;
}

// ---------------------------------------------------------------------------
// Instruction tags
// ---------------------------------------------------------------------------

pub const INIT_POOL_TAG:  u8 = 0x00;
pub const CLAIM_TAG:      u8 = 0x01;
pub const CLOSE_POOL_TAG: u8 = 0x02;

/// PDA seed prefix.
pub const POOL_SEED: &[u8] = b"halo2_reward_pool";

/// Verifier-program tags we'll CPI into.
const VERIFIER_STAGE2_TAG: u8 = 0x03;

// ---------------------------------------------------------------------------
// Pool state — byte-exact, hand-rolled.
// ---------------------------------------------------------------------------

pub const POOL_MAGIC: &[u8; 8] = b"RWPL0001";
pub const POOL_VERSION: u32 = 1;
pub const POOL_BYTES: usize = 8 + 4 + 32 + 32 + 8 + 1 + 8;  // = 93

#[derive(Clone, Copy, Debug)]
pub struct PoolState {
    pub authority:        [u8; 32],
    pub vk_hash_required: [u8; 32],
    pub reward_lamports:  u64,
    pub claimed:          bool,
    pub nonce:            u64,
}

impl PoolState {
    pub fn serialize(&self, out: &mut [u8]) -> Result<(), ProgramError> {
        if out.len() < POOL_BYTES {
            return Err(ProgramError::AccountDataTooSmall);
        }
        out[0..8].copy_from_slice(POOL_MAGIC);
        out[8..12].copy_from_slice(&POOL_VERSION.to_le_bytes());
        out[12..44].copy_from_slice(&self.authority);
        out[44..76].copy_from_slice(&self.vk_hash_required);
        out[76..84].copy_from_slice(&self.reward_lamports.to_le_bytes());
        out[84] = if self.claimed { 1 } else { 0 };
        out[85..93].copy_from_slice(&self.nonce.to_le_bytes());
        // Zero any trailing padding so the byte format is canonical.
        for b in &mut out[POOL_BYTES..] {
            *b = 0;
        }
        Ok(())
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() < POOL_BYTES {
            return Err(ProgramError::Custom(errors::STAGE_STATE_INVALID));
        }
        if &bytes[0..8] != POOL_MAGIC {
            return Err(ProgramError::Custom(errors::STAGE_STATE_INVALID));
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != POOL_VERSION {
            return Err(ProgramError::Custom(errors::STAGE_STATE_INVALID));
        }
        let mut authority = [0u8; 32];
        authority.copy_from_slice(&bytes[12..44]);
        let mut vk_hash_required = [0u8; 32];
        vk_hash_required.copy_from_slice(&bytes[44..76]);
        let reward_lamports = u64::from_le_bytes(bytes[76..84].try_into().unwrap());
        let claimed = bytes[84] != 0;
        let nonce = u64::from_le_bytes(bytes[85..93].try_into().unwrap());
        Ok(Self {
            authority, vk_hash_required, reward_lamports, claimed, nonce,
        })
    }
}

/// Derive the pool PDA: `[POOL_SEED, authority, nonce_le_8]`.
pub fn pool_pda(program_id: &Pubkey, authority: &Pubkey, nonce: u64) -> (Pubkey, u8) {
    let nonce_le = nonce.to_le_bytes();
    Pubkey::find_program_address(
        &[POOL_SEED, authority.as_ref(), &nonce_le],
        program_id,
    )
}

// ---------------------------------------------------------------------------
// Stage1Output decoding (mirror of crates/verifier/src/stage_state.rs).
// We only extract the fields claim() needs: payer, vk_hash, instance_hash.
// ---------------------------------------------------------------------------

/// Byte offsets inside the verifier's `Stage1Output` blob (excluding the
/// 4-byte length prefix in the stage_state account). Mirrors
/// `crates/verifier/src/stage_state.rs` v1.
mod stage_state_layout {
    pub const MAGIC_LEN:    usize = 8;
    pub const MAGIC_BYTES: &[u8; 8] = b"STG10001";
}

/// Walk the Stage1Output bytes (after the length prefix) and pull out
/// the (vk_hash, proof_hash, instance_hash, payer) tuple. Returns
/// `STAGE_STATE_INVALID` on any framing error.
fn extract_stage1_metadata(
    stage1_bytes: &[u8],
) -> Result<([u8; 32], [u8; 32], [u8; 32], [u8; 32]), ProgramError> {
    if stage1_bytes.len() < stage_state_layout::MAGIC_LEN
        || &stage1_bytes[..stage_state_layout::MAGIC_LEN]
            != stage_state_layout::MAGIC_BYTES
    {
        return Err(ProgramError::Custom(errors::STAGE_STATE_INVALID));
    }

    // version u32 + 8 challenges × 32 = 4 + 256 = 260 fixed.
    let mut cur = 8 + 4 + 8 * 32;

    // user_challenges_count u32 LE
    if stage1_bytes.len() < cur + 4 {
        return Err(ProgramError::Custom(errors::STAGE_STATE_INVALID));
    }
    let n_uc = u32::from_le_bytes(stage1_bytes[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4 + 32 * n_uc;

    // 4 lagrange evals + h_eval + h_commit + omega_last
    cur += 4 * 32 + 32 + 64 + 32;

    // instance_evals_count u32 LE
    if stage1_bytes.len() < cur + 4 {
        return Err(ProgramError::Custom(errors::STAGE_STATE_INVALID));
    }
    let n_ie = u32::from_le_bytes(stage1_bytes[cur..cur + 4].try_into().unwrap()) as usize;
    cur += 4 + 32 * n_ie;

    // 3 hashes (vk_hash, proof_hash, instance_hash) + payer + nonce u64
    if stage1_bytes.len() < cur + 32 + 32 + 32 + 32 + 8 {
        return Err(ProgramError::Custom(errors::STAGE_STATE_INVALID));
    }
    let mut vk_hash = [0u8; 32];
    vk_hash.copy_from_slice(&stage1_bytes[cur..cur + 32]);
    cur += 32;
    let mut proof_hash = [0u8; 32];
    proof_hash.copy_from_slice(&stage1_bytes[cur..cur + 32]);
    cur += 32;
    let mut instance_hash = [0u8; 32];
    instance_hash.copy_from_slice(&stage1_bytes[cur..cur + 32]);
    cur += 32;
    let mut payer = [0u8; 32];
    payer.copy_from_slice(&stage1_bytes[cur..cur + 32]);

    Ok((vk_hash, proof_hash, instance_hash, payer))
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let tag = instruction_data
        .first()
        .copied()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let rest = &instruction_data[1..];

    match tag {
        INIT_POOL_TAG  => init_pool(program_id, accounts, rest),
        CLAIM_TAG      => claim(program_id, accounts, rest),
        CLOSE_POOL_TAG => close_pool(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ---------------------------------------------------------------------------
// init_pool
// ---------------------------------------------------------------------------

/// instruction data: `[vk_hash_required: 32B, reward_lamports: u64 LE, nonce: u64 LE]` (48 bytes).
///
/// accounts:
///   0: authority (signer, writable)
///   1: pool_pda  (writable, will be created)
///   2: system_program
fn init_pool(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 32 + 8 + 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut vk_hash_required = [0u8; 32];
    vk_hash_required.copy_from_slice(&data[0..32]);
    let reward_lamports = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let nonce = u64::from_le_bytes(data[40..48].try_into().unwrap());

    let it = &mut accounts.iter();
    let authority = next_account_info(it)?;
    let pool_acct = next_account_info(it)?;
    let system    = next_account_info(it)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if system.key != &system_program::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Verify the supplied pool_pda matches the canonical derivation.
    let (expected_pda, bump) = pool_pda(program_id, authority.key, nonce);
    if expected_pda != *pool_acct.key {
        return Err(ProgramError::InvalidSeeds);
    }

    // CPI into system_program: create_account with `lamports = rent + reward`.
    let rent_lamports = solana_program::rent::Rent::default()
        .minimum_balance(POOL_BYTES);
    let total_lamports = rent_lamports
        .checked_add(reward_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let create_ix = system_instruction::create_account(
        authority.key,
        pool_acct.key,
        total_lamports,
        POOL_BYTES as u64,
        program_id,
    );
    let bump_arr = [bump];
    let signer_seeds: &[&[u8]] = &[
        POOL_SEED,
        authority.key.as_ref(),
        &nonce.to_le_bytes(),
        &bump_arr,
    ];
    solana_program::program::invoke_signed(
        &create_ix,
        &[authority.clone(), pool_acct.clone(), system.clone()],
        &[signer_seeds],
    )?;

    // Write Pool state into the freshly created account.
    let pool = PoolState {
        authority: authority.key.to_bytes(),
        vk_hash_required,
        reward_lamports,
        claimed: false,
        nonce,
    };
    let mut data_mut = pool_acct.try_borrow_mut_data()?;
    pool.serialize(&mut data_mut)?;

    msg!("reward-pool: init_pool ok, locked {} lamports", reward_lamports);
    Ok(())
}

// ---------------------------------------------------------------------------
// claim
// ---------------------------------------------------------------------------

/// instruction data: `[stage2_nonce: u64 LE]` (8 bytes).
///
/// accounts:
///   0: payer              (signer, writable, gets reward)
///   1: pool_pda           (writable, drained for reward)
///   2: data_account       (readonly, owned by verifier program)
///   3: stage_state_acct   (readonly, owned by verifier program)
///   4: verifier_program   (executable, target of the CPI)
fn claim(_program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let stage2_nonce = u64::from_le_bytes(data[0..8].try_into().unwrap());

    let it = &mut accounts.iter();
    let payer            = next_account_info(it)?;
    let pool_acct        = next_account_info(it)?;
    let data_account     = next_account_info(it)?;
    let stage_state_acct = next_account_info(it)?;
    let verifier_program = next_account_info(it)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify pool_pda is owned by us (this program). Without this, anyone
    // could pass a fake pool account and we'd happily drain it.
    if pool_acct.owner != _program_id {
        return Err(ProgramError::Custom(errors::POOL_NOT_OWNED));
    }

    // Read pool state.
    let pool_data = pool_acct.try_borrow_data()?;
    let pool = PoolState::deserialize(&pool_data)?;
    drop(pool_data);

    if pool.claimed {
        return Err(ProgramError::Custom(errors::POOL_ALREADY_CLAIMED));
    }

    // Read Stage1Output from stage_state account.
    let stage_state_data = stage_state_acct.try_borrow_data()?;
    if stage_state_data.len() < 4 {
        return Err(ProgramError::Custom(errors::STAGE_STATE_INVALID));
    }
    let stored_len = u32::from_le_bytes(stage_state_data[0..4].try_into().unwrap()) as usize;
    let end = 4usize.checked_add(stored_len).ok_or(ProgramError::Custom(errors::STAGE_STATE_INVALID))?;
    if end > stage_state_data.len() {
        return Err(ProgramError::Custom(errors::STAGE_STATE_INVALID));
    }
    let (vk_hash, _proof_hash, instance_hash, stage1_payer) =
        extract_stage1_metadata(&stage_state_data[4..end])?;
    drop(stage_state_data);

    // Pool gates only proofs against the specific VK it was created for.
    if vk_hash != pool.vk_hash_required {
        return Err(ProgramError::Custom(errors::VK_HASH_MISMATCH));
    }
    // Stage 1 binds itself to the original caller via
    // `accounts[2].address()` (verifier-program's run_stage1 records the
    // signer's pubkey into Stage1Output.payer). reward-pool requires
    // the same signer here — Eve can't claim against an stage_state
    // Alice computed because the payer field would diverge.
    if stage1_payer != payer.key.to_bytes() {
        return Err(ProgramError::Custom(errors::CLAIMER_HASH_MISMATCH));
    }
    // We deliberately skip instance_hash binding here. For circuits with
    // a non-empty public-inputs vector (e.g. bound-range-check), the
    // verifier itself rejects mismatched public_inputs via Fiat-Shamir
    // divergence, so the per-pool VK gate (`vk_hash_required`) implicitly
    // selects the binding semantics. For zero-instance circuits like
    // range-check the stage1.payer field is the binding.
    let _ = instance_hash;

    // Build the verifier-program::stage2 CPI.
    let mut stage2_data: Vec<u8> = Vec::with_capacity(9);
    stage2_data.push(VERIFIER_STAGE2_TAG);
    stage2_data.extend_from_slice(&stage2_nonce.to_le_bytes());
    let stage2_ix = Instruction {
        program_id: *verifier_program.key,
        accounts: vec![
            AccountMeta::new_readonly(*data_account.key, false),
            AccountMeta::new_readonly(*stage_state_acct.key, false),
            AccountMeta::new(*payer.key, true),
        ],
        data: stage2_data,
    };
    invoke(
        &stage2_ix,
        &[
            data_account.clone(),
            stage_state_acct.clone(),
            payer.clone(),
            verifier_program.clone(),
        ],
    )
    .map_err(|_| ProgramError::Custom(errors::VERIFIER_FAILED))?;

    // Verifier accepted — transfer reward + mark pool claimed.
    **pool_acct.try_borrow_mut_lamports()? = pool_acct
        .lamports()
        .checked_sub(pool.reward_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **payer.try_borrow_mut_lamports()? = payer
        .lamports()
        .checked_add(pool.reward_lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let mut pool_data = pool_acct.try_borrow_mut_data()?;
    let mut new_pool = pool;
    new_pool.claimed = true;
    new_pool.serialize(&mut pool_data)?;

    msg!("reward-pool: claim ok, transferred {} lamports", pool.reward_lamports);
    Ok(())
}

// ---------------------------------------------------------------------------
// close_pool
// ---------------------------------------------------------------------------

/// instruction data: empty.
///
/// accounts:
///   0: authority (signer, writable, receives the lamports)
///   1: pool_pda  (writable, drained)
fn close_pool(program_id: &Pubkey, accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let it = &mut accounts.iter();
    let authority = next_account_info(it)?;
    let pool_acct = next_account_info(it)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if pool_acct.owner != program_id {
        return Err(ProgramError::Custom(errors::POOL_NOT_OWNED));
    }

    let pool_data = pool_acct.try_borrow_data()?;
    let pool = PoolState::deserialize(&pool_data)?;
    drop(pool_data);

    if pool.authority != authority.key.to_bytes() {
        return Err(ProgramError::Custom(errors::POOL_AUTHORITY_MISMATCH));
    }

    // Drain all lamports back to authority.
    let to_refund = pool_acct.lamports();
    **pool_acct.try_borrow_mut_lamports()? = 0;
    **authority.try_borrow_mut_lamports()? = authority
        .lamports()
        .checked_add(to_refund)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Zero the pool data so the account is recognisably closed.
    let mut data_mut = pool_acct.try_borrow_mut_data()?;
    for b in data_mut.iter_mut() { *b = 0; }

    msg!("reward-pool: close_pool ok, refunded {} lamports", to_refund);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_state_roundtrip() {
        let pool = PoolState {
            authority: [0xAA; 32],
            vk_hash_required: [0xBB; 32],
            reward_lamports: 100_000_000,
            claimed: false,
            nonce: 0x1122_3344_5566_7788,
        };
        let mut bytes = vec![0u8; POOL_BYTES + 16]; // padding tail
        pool.serialize(&mut bytes).unwrap();
        let restored = PoolState::deserialize(&bytes).unwrap();
        assert_eq!(restored.authority, pool.authority);
        assert_eq!(restored.vk_hash_required, pool.vk_hash_required);
        assert_eq!(restored.reward_lamports, pool.reward_lamports);
        assert_eq!(restored.claimed, pool.claimed);
        assert_eq!(restored.nonce, pool.nonce);
    }

    #[test]
    fn pool_state_rejects_bad_magic() {
        let pool = PoolState {
            authority: [0; 32],
            vk_hash_required: [0; 32],
            reward_lamports: 1,
            claimed: false,
            nonce: 0,
        };
        let mut bytes = vec![0u8; POOL_BYTES];
        pool.serialize(&mut bytes).unwrap();
        bytes[0] = b'X';
        assert!(matches!(
            PoolState::deserialize(&bytes),
            Err(ProgramError::Custom(errors::STAGE_STATE_INVALID))
        ));
    }

    #[test]
    fn pool_state_rejects_short_buffer() {
        let bytes = vec![0u8; POOL_BYTES - 1];
        assert!(matches!(
            PoolState::deserialize(&bytes),
            Err(ProgramError::Custom(errors::STAGE_STATE_INVALID))
        ));
    }

    /// Stage1Output extraction walks the variable-size sections correctly.
    #[test]
    fn extract_stage1_metadata_picks_replay_hashes() {
        // Synth the Stage1Output blob with empty user_challenges + 1
        // instance_eval. Layout: 8 magic + 4 ver + 8×32 ch + 4 (n_uc=0) +
        // 4×32 lag + 32 h_eval + 64 h_commit + 32 omega_last + 4 (n_ie=1)
        // + 32 instance_eval + 32 vk_hash + 32 proof_hash + 32 instance_hash
        // + 32 payer + 8 nonce.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"STG10001");
        bytes.extend_from_slice(&1u32.to_le_bytes());     // version
        for _ in 0..8 { bytes.extend_from_slice(&[0u8; 32]); }   // 8 challenges
        bytes.extend_from_slice(&0u32.to_le_bytes());     // n_uc = 0
        for _ in 0..4 { bytes.extend_from_slice(&[0u8; 32]); }   // 4 lagrange
        bytes.extend_from_slice(&[0u8; 32]);              // h_eval
        bytes.extend_from_slice(&[0u8; 64]);              // h_commit
        bytes.extend_from_slice(&[0u8; 32]);              // omega_last
        bytes.extend_from_slice(&1u32.to_le_bytes());     // n_ie = 1
        bytes.extend_from_slice(&[0u8; 32]);              // 1 instance eval
        bytes.extend_from_slice(&[0xAA; 32]);             // vk_hash
        bytes.extend_from_slice(&[0xBB; 32]);             // proof_hash
        bytes.extend_from_slice(&[0xCC; 32]);             // instance_hash
        bytes.extend_from_slice(&[0xDD; 32]);             // payer
        bytes.extend_from_slice(&0u64.to_le_bytes());     // nonce

        let (vk, proof, instance, payer) = extract_stage1_metadata(&bytes).unwrap();
        assert_eq!(vk,       [0xAA; 32]);
        assert_eq!(proof,    [0xBB; 32]);
        assert_eq!(instance, [0xCC; 32]);
        assert_eq!(payer,    [0xDD; 32]);
    }
}
