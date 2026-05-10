//! Solana BPF program wrapping `halo2_solana_verifier::verify`.
//!
//! Single instruction: parse the on-chain test vector format from
//! `instruction_data`, call the verifier, return Ok/Err.
//!
//! Instruction data layout (matches `gen-proof --write-golden`):
//!
//! ```text
//!   magic              : [u8; 8]    = b"GLDN0001"
//!   vk_len             : u32 LE
//!   vk_bytes           : [u8; vk_len]
//!   proof_len          : u32 LE
//!   proof_bytes        : [u8; proof_len]
//!   kzg_g1_one         : [u8; 64]   (BE: x ‖ y)
//!   kzg_g2_one         : [u8; 128]  (BE: x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0)
//!   kzg_g2_tau         : [u8; 128]  (BE: x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0)
//! ```
//!
//! Public inputs are passed as a flat byte stream of additional 32-B BE
//! scalars after the kzg_g2_tau region. v1 uses zero public inputs, so
//! anything beyond the fixed footer is rejected.
//!
//! On success, returns `Ok(())`. On verifier reject (proof invalid),
//! returns `ProgramError::Custom(VERIFIER_REJECTED)`. On parse error,
//! returns `ProgramError::Custom(MALFORMED_INPUT)`.

#![no_std]

extern crate alloc;

use halo2_solana_verifier::{kzg::KzgVk, verify, curve::{G1, G2}};

const MAGIC: &[u8; 8] = b"GLDN0001";
const G1_LEN: usize = 64;
const G2_LEN: usize = 128;

/// Custom error codes for the program. Logged via `ProgramError::Custom`.
pub mod errors {
    pub const MALFORMED_INPUT:    u32 = 0x100;
    pub const VK_OUT_OF_BOUNDS:   u32 = 0x101;
    pub const PROOF_OUT_OF_BOUNDS: u32 = 0x102;
    pub const KZG_OUT_OF_BOUNDS:  u32 = 0x103;
    pub const VERIFIER_REJECTED:  u32 = 0x200;
    pub const VERIFIER_ERROR:     u32 = 0x201;
    pub const LOAD_OOB:           u32 = 0x300;
    pub const NO_ACCOUNT:         u32 = 0x301;
}

/// Instruction tags carried in `instruction_data[0]`.
pub const VERIFY_TAG: u8 = 0x00;
pub const LOAD_TAG:   u8 = 0x01;

/// Parse the on-chain instruction-data layout into the inputs `verify()` needs.
/// `no_std`-friendly; allocations only happen inside `verify()`'s temporaries.
fn parse_instruction(data: &[u8])
    -> Result<(&[u8], &[u8], KzgVk, alloc::vec::Vec<[u8; 32]>), u32>
{
    if data.len() < 8 + 4 || &data[..8] != MAGIC {
        return Err(errors::MALFORMED_INPUT);
    }
    let mut cur = 8usize;

    // vk
    let vk_len = read_u32_le(data, &mut cur)? as usize;
    let vk_end = cur.checked_add(vk_len).ok_or(errors::MALFORMED_INPUT)?;
    if vk_end > data.len() { return Err(errors::VK_OUT_OF_BOUNDS); }
    let vk_bytes = &data[cur..vk_end];
    cur = vk_end;

    // proof
    let proof_len = read_u32_le(data, &mut cur)? as usize;
    let proof_end = cur.checked_add(proof_len).ok_or(errors::MALFORMED_INPUT)?;
    if proof_end > data.len() { return Err(errors::PROOF_OUT_OF_BOUNDS); }
    let proof_bytes = &data[cur..proof_end];
    cur = proof_end;

    // kzg_vk
    let kzg_total = G1_LEN + 2 * G2_LEN;
    if data.len().saturating_sub(cur) < kzg_total {
        return Err(errors::KZG_OUT_OF_BOUNDS);
    }
    let mut g1_one_bytes = [0u8; G1_LEN];
    g1_one_bytes.copy_from_slice(&data[cur..cur + G1_LEN]);
    cur += G1_LEN;

    let mut g2_one_bytes = [0u8; G2_LEN];
    g2_one_bytes.copy_from_slice(&data[cur..cur + G2_LEN]);
    cur += G2_LEN;

    let mut g2_tau_bytes = [0u8; G2_LEN];
    g2_tau_bytes.copy_from_slice(&data[cur..cur + G2_LEN]);
    cur += G2_LEN;

    // v1.5: optional public-inputs suffix `[n_pi: u32 LE | pi: 32 B × n_pi]`.
    // v1.0 payloads (no PIs) end exactly here; we treat both layouts as valid.
    let public_inputs: alloc::vec::Vec<[u8; 32]> = if cur == data.len() {
        alloc::vec::Vec::new()
    } else {
        let n_pi = read_u32_le(data, &mut cur)? as usize;
        let want = n_pi.checked_mul(32).ok_or(errors::MALFORMED_INPUT)?;
        if cur.checked_add(want).map_or(true, |e| e != data.len()) {
            return Err(errors::MALFORMED_INPUT);
        }
        let mut pis = alloc::vec::Vec::with_capacity(n_pi);
        for _ in 0..n_pi {
            let mut pi = [0u8; 32];
            pi.copy_from_slice(&data[cur..cur + 32]);
            pis.push(pi);
            cur += 32;
        }
        pis
    };

    Ok((vk_bytes, proof_bytes, KzgVk {
        g1_one: G1(g1_one_bytes),
        g2_one: G2(g2_one_bytes),
        g2_tau: G2(g2_tau_bytes),
    }, public_inputs))
}

#[inline]
fn read_u32_le(data: &[u8], cur: &mut usize) -> Result<u32, u32> {
    if cur.checked_add(4).map_or(true, |e| e > data.len()) {
        return Err(errors::MALFORMED_INPUT);
    }
    let v = u32::from_le_bytes([data[*cur], data[*cur + 1], data[*cur + 2], data[*cur + 3]]);
    *cur += 4;
    Ok(v)
}

/// Pure verification step — independent of pinocchio account / pubkey types.
/// Returns the program-error u32 on failure, or `Ok(())` on a verified proof.
///
/// Several `probe-*` features short-circuit at progressively deeper stages
/// to isolate which BPF code path causes Mollusk's CU exhaustion. The
/// `stage-trace` feature instead runs the full verify but emits
/// `sol_log_compute_units_` after every stage, producing a per-stage
/// breakdown in the program log.
pub fn run(instruction_data: &[u8]) -> Result<(), u32> {
    #[cfg(feature = "probe-noop")]
    {
        // Don't even parse — purely confirms the BPF VM + Pinocchio entrypoint
        // + Mollusk plumbing all work end-to-end with this crate.
        let _ = instruction_data;
        return Ok(());
    }
    #[allow(unreachable_code)]
    {
        let (vk_bytes, proof_bytes, kzg_vk, public_inputs) = parse_instruction(instruction_data)?;

        #[cfg(feature = "probe-parse-vk")]
        {
            let _ = halo2_solana_verifier::vk::parse_vk(vk_bytes)
                .map_err(|_| errors::VERIFIER_ERROR)?;
            let _ = (proof_bytes, kzg_vk, &public_inputs);
            return Ok(());
        }

        #[cfg(feature = "probe-read-proof")]
        {
            let vk = halo2_solana_verifier::vk::parse_vk(vk_bytes)
                .map_err(|_| errors::VERIFIER_ERROR)?;
            let mut transcript =
                halo2_solana_verifier::transcript::Keccak256Transcript::new(&vk.transcript_repr);
            let _ = halo2_solana_verifier::proof_reader::read_proof(
                &vk, proof_bytes, &public_inputs, &mut transcript,
            ).map_err(|_| errors::VERIFIER_ERROR)?;
            let _ = kzg_vk;
            return Ok(());
        }

        #[cfg(feature = "stage-trace")]
        return run_traced(vk_bytes, proof_bytes, kzg_vk, public_inputs);

        // Default: full verify.
        #[allow(unreachable_code)]
        {
            match verify(vk_bytes, proof_bytes, &public_inputs, &kzg_vk) {
                Ok(true)  => Ok(()),
                Ok(false) => Err(errors::VERIFIER_REJECTED),
                Err(_)    => Err(errors::VERIFIER_ERROR),
            }
        }
    }
}

/// Stage-by-stage verify with `sol_log_compute_units_` between each step.
/// Builds nothing the default path doesn't also build, so the per-stage
/// CU readings reflect production code (modulo the cost of the syscalls
/// themselves, which are uniform).
/// Lifts the instance-eval reconstruction out of `run_traced` so its
/// `Vec<Vec<Fr>>` intermediates live in a separate BPF stack frame.
#[cfg(feature = "stage-trace")]
#[inline(never)]
fn reconstruct_instance_evals_helper(
    vk: &halo2_solana_verifier::plonk::PlonkProtocol,
    x: ark_bn254::Fr,
    public_inputs: &[[u8; 32]],
) -> Result<alloc::vec::Vec<ark_bn254::Fr>, u32> {
    if vk.num_instance == 0 {
        return Ok(alloc::vec::Vec::new());
    }
    let mut col0 = alloc::vec::Vec::with_capacity(public_inputs.len());
    for raw in public_inputs {
        col0.push(halo2_solana_verifier::field::fr_from_bytes_be(raw)
            .map_err(|_| errors::VERIFIER_ERROR)?);
    }
    let mut cols: alloc::vec::Vec<alloc::vec::Vec<ark_bn254::Fr>> = alloc::vec::Vec::new();
    cols.push(col0);
    for _ in 1..vk.num_instance {
        cols.push(alloc::vec::Vec::new());
    }
    halo2_solana_verifier::plonk::lagrange::reconstruct_instance_evals(
        vk.k, vk.omega, x, &vk.instance_queries, &cols,
    ).map_err(|_| errors::VERIFIER_ERROR)
}

/// `ω^(n − blinding_factors − 1)` — used by `build_queries`. Lifted out
/// of `run_traced` for the same stack-frame reason as above.
#[cfg(feature = "stage-trace")]
#[inline(never)]
fn compute_omega_last(k: u32, omega: ark_bn254::Fr, blinding_factors: usize) -> ark_bn254::Fr {
    let n: u64 = 1u64 << k;
    let last_pow = n.saturating_sub(blinding_factors as u64 + 1);
    let mut acc = ark_bn254::Fr::from(1u64);
    let mut base = omega;
    let mut exp = last_pow;
    while exp != 0 {
        if exp & 1 == 1 { acc *= base; }
        base = base * base;
        exp >>= 1;
    }
    acc
}

#[cfg(feature = "stage-trace")]
fn run_traced(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    kzg_vk: KzgVk,
    public_inputs: alloc::vec::Vec<[u8; 32]>,
) -> Result<(), u32> {
    use halo2_solana_verifier::{
        plonk::{lagrange, permutation, verifier as v, PlonkProof, PlonkProtocol, Challenges},
        transcript::Keccak256Transcript,
        proof_reader, kzg::shplonk, pairing,
    };

    #[cfg(target_os = "solana")]
    fn cu(label: &str) {
        unsafe {
            pinocchio::syscalls::sol_log_(label.as_ptr(), label.len() as u64);
            pinocchio::syscalls::sol_log_compute_units_();
        }
    }
    #[cfg(not(target_os = "solana"))]
    fn cu(_label: &str) {}

    cu("[stage] enter");
    let vk: PlonkProtocol = halo2_solana_verifier::vk::parse_vk(vk_bytes)
        .map_err(|_| errors::VERIFIER_ERROR)?;
    cu("[stage] after parse_vk");

    let mut transcript = Keccak256Transcript::new(&vk.transcript_repr);
    let (proof, ch): (PlonkProof, Challenges) = proof_reader::read_proof(
        &vk, proof_bytes, &public_inputs, &mut transcript,
    ).map_err(|_| errors::VERIFIER_ERROR)?;
    cu("[stage] after read_proof");

    let lag = lagrange::evaluate_lagrange(vk.k, vk.omega, ch.x, vk.blinding_factors)
        .map_err(|_| errors::VERIFIER_ERROR)?;
    cu("[stage] after lagrange");

    let instance_evals = reconstruct_instance_evals_helper(&vk, ch.x, &public_inputs)?;
    let user_challenges: alloc::vec::Vec<ark_bn254::Fr> = alloc::vec::Vec::new();
    let expected_h_eval = v::compute_expected_h_eval(
        &vk, &proof, &ch, &lag, &instance_evals, &user_challenges,
    ).map_err(|_| errors::VERIFIER_ERROR)?;
    cu("[stage] after expected_h_eval");
    let _ = expected_h_eval;

    let h_commit = v::aggregate_h_commitment(&proof.vanishing_h_commits, lag.xn)
        .map_err(|_| errors::VERIFIER_ERROR)?;
    cu("[stage] after h_commit");

    let omega_last = compute_omega_last(vk.k, vk.omega, vk.blinding_factors);
    cu("[stage] after omega_last");

    let queries = v::build_queries(&vk, &proof, &ch, h_commit, expected_h_eval, vk.omega, omega_last)
        .map_err(|_| errors::VERIFIER_ERROR)?;
    cu("[stage] after build_queries");

    let pairs = shplonk::verify_opening(
        &queries, proof.opening_proof_w, proof.opening_proof_w_prime,
        ch.shplonk_y, ch.shplonk_v, ch.shplonk_u, &kzg_vk,
    ).map_err(|_| errors::VERIFIER_ERROR)?;
    cu("[stage] after shplonk::verify_opening");

    let ok = pairing::pairing_check(&pairs.0).map_err(|_| errors::VERIFIER_ERROR)?;
    cu("[stage] after pairing");

    if ok { Ok(()) } else { Err(errors::VERIFIER_REJECTED) }
}

// ---------------------------------------------------------------------------
// Pinocchio entrypoint (only when building the .so).
// ---------------------------------------------------------------------------

#[cfg(feature = "bpf-entrypoint")]
mod entry {
    use pinocchio::{
        account::AccountView, address::Address, entrypoint,
        error::ProgramError, ProgramResult,
    };

    entrypoint!(process_instruction);

    /// Solana tx max = 1232 bytes; the golden vector alone is 2312 B. So we
    /// pass the verify input through a *data account* (`accounts[0]`) which
    /// the off-chain helper populates with a sequence of LOAD instructions.
    ///
    /// Tag dispatch:
    ///   * `[VERIFY_TAG]`               + accounts[0] readonly  → verify
    ///   * `[LOAD_TAG, offset_le, ...]` + accounts[0] writable  → memcpy
    ///   * (empty)                                              → host-test path
    fn process_instruction(
        _program_id: &Address,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        if let Some(tag) = instruction_data.first().copied() {
            if tag == super::LOAD_TAG {
                if accounts.is_empty() {
                    return Err(ProgramError::Custom(super::errors::NO_ACCOUNT));
                }
                if instruction_data.len() < 5 {
                    return Err(ProgramError::Custom(super::errors::LOAD_OOB));
                }
                let offset = u32::from_le_bytes([
                    instruction_data[1], instruction_data[2],
                    instruction_data[3], instruction_data[4],
                ]) as usize;
                let chunk = &instruction_data[5..];
                let acct = &mut accounts[0];
                // SAFETY: caller guarantees writable borrow.
                let dst: &mut [u8] = unsafe { acct.borrow_unchecked_mut() };
                if offset.checked_add(chunk.len()).map_or(true, |e| e > dst.len()) {
                    return Err(ProgramError::Custom(super::errors::LOAD_OOB));
                }
                dst[offset..offset + chunk.len()].copy_from_slice(chunk);
                return Ok(());
            }
            if tag == super::VERIFY_TAG && !accounts.is_empty() {
                let acct = &accounts[0];
                let data: &[u8] = unsafe { acct.borrow_unchecked() };
                return super::run(data).map_err(ProgramError::Custom);
            }
        }
        // Fallback: small inputs that fit inside instruction_data (host tests).
        super::run(instruction_data).map_err(ProgramError::Custom)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn build_instruction(vk: &[u8], proof: &[u8], kzg: &KzgVk) -> std::vec::Vec<u8> {
        let mut buf = std::vec::Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&(vk.len() as u32).to_le_bytes());
        buf.extend_from_slice(vk);
        buf.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        buf.extend_from_slice(proof);
        buf.extend_from_slice(&kzg.g1_one.0);
        buf.extend_from_slice(&kzg.g2_one.0);
        buf.extend_from_slice(&kzg.g2_tau.0);
        buf
    }

    #[test]
    fn parse_round_trip() {
        let vk = std::vec![1u8; 17];
        let proof = std::vec![2u8; 33];
        let kzg = KzgVk {
            g1_one: G1([3u8; 64]),
            g2_one: G2([4u8; 128]),
            g2_tau: G2([5u8; 128]),
        };
        let buf = build_instruction(&vk, &proof, &kzg);
        let (got_vk, got_proof, got_kzg, got_pis) = parse_instruction(&buf).unwrap();
        assert!(got_pis.is_empty(), "v1 layout has no PI suffix");
        assert_eq!(got_vk, vk.as_slice());
        assert_eq!(got_proof, proof.as_slice());
        assert_eq!(got_kzg.g1_one.0, kzg.g1_one.0);
        assert_eq!(got_kzg.g2_one.0, kzg.g2_one.0);
        assert_eq!(got_kzg.g2_tau.0, kzg.g2_tau.0);
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut buf = build_instruction(&[1, 2, 3], &[4, 5], &KzgVk {
            g1_one: G1([0; 64]), g2_one: G2([0; 128]), g2_tau: G2([0; 128]),
        });
        buf[0] = b'X';
        assert_eq!(parse_instruction(&buf).unwrap_err(), errors::MALFORMED_INPUT);
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let mut buf = build_instruction(&[1, 2, 3], &[4, 5], &KzgVk {
            g1_one: G1([0; 64]), g2_one: G2([0; 128]), g2_tau: G2([0; 128]),
        });
        buf.push(0xFF);
        assert_eq!(parse_instruction(&buf).unwrap_err(), errors::MALFORMED_INPUT);
    }

    /// End-to-end: parse the golden vector from disk and run `run()` —
    /// verifies the BPF code path top-to-bottom on host syscall emulation.
    #[test]
    fn run_golden_vector_passes() {
        let path = "../../circuits/standard-plonk/tests/golden_v1.bin";
        let buf = std::fs::read(path)
            .expect("run `cargo run -p standard-plonk-circuit --bin gen-proof -- --write-golden` first");
        run(&buf).expect("verifier should accept a valid proof");
    }
}
