//! 2-tx split: the intermediate state passed from STAGE1 to STAGE2.
//!
//! STAGE1 runs the verifier up through `compute_expected_h_eval` and the
//! `aggregate_h_commitment` step, then writes the derived state into a
//! per-payer PDA. STAGE2 reads the PDA, re-derives the replay-binding
//! hashes from the data account, compares, and runs the remaining
//! `build_queries` + `shplonk::verify_opening` + `pairing` work.
//!
//! Why split here. The natural seam is right after `expected_h_eval`:
//! it's where `lagrange::evaluate_lagrange` (~540k CU) finishes and
//! before `shplonk::verify_opening` (~530-1670k CU) starts. Both halves
//! independently fit under Solana's 1.4 M default per-tx CU cap for the
//! lookup / shuffle / multi-lookup circuits.
//!
//! Replay protection. The PDA stores three keccak256 hashes of the input
//! (`vk_bytes`, `proof_bytes`, `public_inputs`). STAGE2 re-computes them
//! from the same data account and rejects on mismatch. The PDA seed
//! includes the payer pubkey + a per-attempt nonce, so two concurrent
//! verifies don't collide and a different payer can't piggyback on a
//! stage1 they didn't run.
//!
//! This file is the *byte format* + serialization of `Stage1Output`. The
//! actual stage1/stage2 dispatch lives in `programs/verifier-program/`;
//! the replay-hash helper is intentionally here so both sides agree on
//! the canonical hashing.

use alloc::vec::Vec;
use ark_bn254::Fr;

use crate::{
    curve::{G1, G2},
    field::{fr_from_bytes_be, fr_to_bytes_be},
    plonk::{lagrange::LagrangeEvaluations, Challenges},
    Error,
};

/// Magic prefix for a `Stage1Output` blob. Bumping this forces stage2 to
/// reject blobs from older verifier binaries.
pub const STAGE_STATE_MAGIC: &[u8; 8] = b"STG10001";
pub const STAGE_STATE_VERSION: u32 = 1;

/// Magic prefix for a `Stage2Output` blob (3-tx split: stage2a → stage3).
pub const STAGE2_STATE_MAGIC: &[u8; 8] = b"STG20001";
pub const STAGE2_STATE_VERSION: u32 = 1;

/// Hard cap on `Stage2Output::msm_terms.len()`. Stage 2a's
/// `build_shplonk_msm_terms` produces one term per query plus three
/// finalization terms (`-r_outer·[1]₁`, `-z_0·h1`, `u·h2`). For the
/// reference circuits this stays under 50; 256 leaves headroom for
/// larger halo2 shapes.
pub const MAX_MSM_TERMS: usize = 256;

/// Hard cap on `user_challenges.len()`. Prevents a malformed PDA from
/// requesting an oversized allocation in deserialize. Real circuits use
/// 0–4 user challenges.
pub const MAX_USER_CHALLENGES: usize = 32;

/// Hard cap on `instance_evals.len()`. Real circuits use 0–8 instance
/// evals (one per instance query).
pub const MAX_INSTANCE_EVALS: usize = 32;

/// Everything stage1 derives that stage2 needs. Serialised into a
/// per-payer PDA between txs.
#[derive(Clone, Debug)]
pub struct Stage1Output {
    // Fiat–Shamir challenges (8 × Fr).
    pub theta: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub y: Fr,
    pub x: Fr,
    pub shplonk_y: Fr,
    pub shplonk_v: Fr,
    pub shplonk_u: Fr,
    /// User-defined phase challenges; matches `Challenges::user_challenges`.
    pub user_challenges: Vec<Fr>,

    // Lagrange evaluations at x.
    pub l_0: Fr,
    pub l_last: Fr,
    pub l_blind: Fr,
    pub xn: Fr,

    /// `expected_h_eval` from `compute_expected_h_eval`.
    pub expected_h_eval: Fr,
    /// `h_commitment = Σᵢ xnⁱ · vanishing_h_pieces[i]` from `aggregate_h_commitment`.
    pub h_commitment: G1,
    /// `omega^(n − blinding − 1)` — used by `build_queries` for permutation z_last point.
    pub omega_last: Fr,
    /// Reconstructed instance evaluations (Lagrange basis, see lagrange.rs).
    pub instance_evals: Vec<Fr>,

    // Replay binding — keccak256 of the canonical inputs at stage1 time.
    /// `keccak256(vk_bytes)`.
    pub vk_hash: [u8; 32],
    /// `keccak256(proof_bytes)`.
    pub proof_hash: [u8; 32],
    /// `keccak256(public_inputs flattened, 32 bytes per Fr in BE order)`.
    pub instance_hash: [u8; 32],

    /// 32-byte Solana pubkey of the stage1 caller. Stage2 must be signed
    /// by the same key, and the PDA seed must include this pubkey.
    pub payer: [u8; 32],
    /// Per-attempt nonce; binds the PDA seed and prevents account collisions
    /// across concurrent verifies by the same payer.
    pub nonce: u64,
}

impl Stage1Output {
    /// Append the canonical byte representation to `out`. Returns
    /// `InvalidStageState` if `user_challenges` or `instance_evals`
    /// exceed the hard caps.
    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.user_challenges.len() > MAX_USER_CHALLENGES {
            return Err(Error::InvalidStageState);
        }
        if self.instance_evals.len() > MAX_INSTANCE_EVALS {
            return Err(Error::InvalidStageState);
        }

        out.extend_from_slice(STAGE_STATE_MAGIC);
        out.extend_from_slice(&STAGE_STATE_VERSION.to_le_bytes());

        // Challenges (8 × Fr BE).
        for f in [
            &self.theta, &self.beta, &self.gamma, &self.y, &self.x,
            &self.shplonk_y, &self.shplonk_v, &self.shplonk_u,
        ] {
            out.extend_from_slice(&fr_to_bytes_be(f));
        }

        // user_challenges: u32 LE count, then n × 32 B.
        out.extend_from_slice(&(self.user_challenges.len() as u32).to_le_bytes());
        for f in &self.user_challenges {
            out.extend_from_slice(&fr_to_bytes_be(f));
        }

        // Lagrange evaluations.
        for f in [&self.l_0, &self.l_last, &self.l_blind, &self.xn] {
            out.extend_from_slice(&fr_to_bytes_be(f));
        }

        // Verifier intermediates.
        out.extend_from_slice(&fr_to_bytes_be(&self.expected_h_eval));
        out.extend_from_slice(&self.h_commitment.0);
        out.extend_from_slice(&fr_to_bytes_be(&self.omega_last));

        // instance_evals: u32 LE count, then n × 32 B.
        out.extend_from_slice(&(self.instance_evals.len() as u32).to_le_bytes());
        for f in &self.instance_evals {
            out.extend_from_slice(&fr_to_bytes_be(f));
        }

        // Replay-binding hashes.
        out.extend_from_slice(&self.vk_hash);
        out.extend_from_slice(&self.proof_hash);
        out.extend_from_slice(&self.instance_hash);

        // Authority binding.
        out.extend_from_slice(&self.payer);
        out.extend_from_slice(&self.nonce.to_le_bytes());

        Ok(())
    }

    /// Inverse of `serialize`. Strict: any trailing bytes, wrong magic
    /// or version, or count > cap → `InvalidStageState`.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut cur = 0usize;

        let magic = read_array::<8>(bytes, &mut cur)?;
        if &magic != STAGE_STATE_MAGIC {
            return Err(Error::InvalidStageState);
        }
        let version = read_u32_le(bytes, &mut cur)?;
        if version != STAGE_STATE_VERSION {
            return Err(Error::InvalidStageState);
        }

        let theta = read_fr(bytes, &mut cur)?;
        let beta = read_fr(bytes, &mut cur)?;
        let gamma = read_fr(bytes, &mut cur)?;
        let y = read_fr(bytes, &mut cur)?;
        let x = read_fr(bytes, &mut cur)?;
        let shplonk_y = read_fr(bytes, &mut cur)?;
        let shplonk_v = read_fr(bytes, &mut cur)?;
        let shplonk_u = read_fr(bytes, &mut cur)?;

        let n_uc = read_u32_le(bytes, &mut cur)? as usize;
        if n_uc > MAX_USER_CHALLENGES {
            return Err(Error::InvalidStageState);
        }
        let mut user_challenges = Vec::with_capacity(n_uc);
        for _ in 0..n_uc {
            user_challenges.push(read_fr(bytes, &mut cur)?);
        }

        let l_0 = read_fr(bytes, &mut cur)?;
        let l_last = read_fr(bytes, &mut cur)?;
        let l_blind = read_fr(bytes, &mut cur)?;
        let xn = read_fr(bytes, &mut cur)?;

        let expected_h_eval = read_fr(bytes, &mut cur)?;
        let h_commitment = G1(read_array::<64>(bytes, &mut cur)?);
        let omega_last = read_fr(bytes, &mut cur)?;

        let n_ie = read_u32_le(bytes, &mut cur)? as usize;
        if n_ie > MAX_INSTANCE_EVALS {
            return Err(Error::InvalidStageState);
        }
        let mut instance_evals = Vec::with_capacity(n_ie);
        for _ in 0..n_ie {
            instance_evals.push(read_fr(bytes, &mut cur)?);
        }

        let vk_hash = read_array::<32>(bytes, &mut cur)?;
        let proof_hash = read_array::<32>(bytes, &mut cur)?;
        let instance_hash = read_array::<32>(bytes, &mut cur)?;

        let payer = read_array::<32>(bytes, &mut cur)?;
        let nonce_bytes = read_array::<8>(bytes, &mut cur)?;
        let nonce = u64::from_le_bytes(nonce_bytes);

        if cur != bytes.len() {
            return Err(Error::InvalidStageState);
        }

        Ok(Stage1Output {
            theta, beta, gamma, y, x, shplonk_y, shplonk_v, shplonk_u,
            user_challenges,
            l_0, l_last, l_blind, xn,
            expected_h_eval, h_commitment, omega_last,
            instance_evals,
            vk_hash, proof_hash, instance_hash,
            payer, nonce,
        })
    }

    /// Number of bytes the canonical serialization will produce. Useful
    /// for sizing the PDA before stage1 writes.
    pub fn serialized_size(&self) -> usize {
        const FIXED: usize =
              8                 // magic
            + 4                 // version
            + 8 * 32            // 8 challenges
            + 4                 // user_challenges count
            + 4 * 32            // 4 lagrange evals
            + 32                // expected_h_eval
            + 64                // h_commitment
            + 32                // omega_last
            + 4                 // instance_evals count
            + 32 + 32 + 32      // 3 hashes
            + 32                // payer
            + 8;                // nonce
        FIXED + 32 * (self.user_challenges.len() + self.instance_evals.len())
    }

    /// Reconstruct the `Challenges` struct stage2 hands to
    /// `compute_expected_h_eval`'s downstream consumers.
    pub fn challenges(&self) -> Challenges {
        Challenges {
            theta: self.theta,
            beta: self.beta,
            gamma: self.gamma,
            y: self.y,
            x: self.x,
            shplonk_y: self.shplonk_y,
            shplonk_v: self.shplonk_v,
            shplonk_u: self.shplonk_u,
            user_challenges: self.user_challenges.clone(),
        }
    }

    /// Reconstruct the `LagrangeEvaluations` struct stage2 hands to
    /// `build_queries`.
    pub fn lagrange(&self) -> LagrangeEvaluations {
        LagrangeEvaluations {
            l_0: self.l_0,
            l_last: self.l_last,
            l_blind: self.l_blind,
            xn: self.xn,
        }
    }
}

// ---------------------------------------------------------------------------
// 3-tx split: Stage2Output (handed from stage2a to stage3).
//
// The 3-tx split breaks verify into:
//   * stage1   — parse_vk + read_proof + lagrange + expected_h_eval + h_commit
//                + omega_last  → writes Stage1Output
//   * stage2a  — read Stage1Output + parse_proof_no_fs + build_queries +
//                `shplonk::build_shplonk_msm_terms` (phase 1: rotation-set
//                algebra + lagrange interpolations, all Fr math)
//                → writes Stage2Output
//   * stage3   — read Stage2Output + `shplonk::finalize_shplonk_pairs`
//                (phase 2: single G1 MSM) + `alt_bn128_pairing`
//
// Why splitting *inside* shplonk: pre-split measurement showed shplonk +
// pairing alone hit ~1.5 M CU for Fibonacci, busting the 1.4 M cap even
// when nothing else lived in stage3. The MSM is ~N syscalls of ~30 k CU
// each; pushing the term-building (pure Fr math, ~600 k CU on Fibonacci)
// into stage2a leaves stage3 with just the MSM syscalls and the pairing
// (~800–900 k CU total).
//
// Replay binding. Stage3 doesn't read the data account — `Stage2Output`
// is program-owned, so the program already validated its contents during
// stage 2a. Stage3 only checks payer + nonce against the persisted values
// (signer mismatch / nonce mismatch → STAGE_AUTH_MISMATCH).
// ---------------------------------------------------------------------------

/// Output of stage2a (parse_proof_no_fs + build_queries + shplonk phase 1).
/// Stage3 consumes this to finish the SHPLONK MSM and run the pairing
/// without needing the data account.
#[derive(Clone, Debug)]
pub struct Stage2Output {
    /// Outer-MSM terms after shplonk phase 1, finalization terms already
    /// appended. Stage3 feeds these into one `msm_g1` syscall.
    pub msm_terms: Vec<(Fr, G1)>,

    /// `h2 = opening_proof_w_prime` — needed as the first pairing-pair G1.
    pub opening_proof_w_prime: G1,

    /// KZG verification key fields persisted so stage3 doesn't need the
    /// data account. `g1_one` was already consumed inside phase 1 as one
    /// of the MSM terms, so it's not carried here.
    pub kzg_g2_one: G2,
    pub kzg_g2_tau: G2,

    /// Replay-binding hashes — same triple Stage1Output carries. Forwarded
    /// for diagnostic / external-binding use; stage3 doesn't re-derive them
    /// because it doesn't read the data account.
    pub vk_hash: [u8; 32],
    pub proof_hash: [u8; 32],
    pub instance_hash: [u8; 32],

    /// 32-byte Solana pubkey of the verifier caller. Stage3 must be signed
    /// by the same key.
    pub payer: [u8; 32],
    /// Per-attempt nonce; binds to the PDA seed across stages.
    pub nonce: u64,
}

impl Stage2Output {
    /// Wire size of one MSM term: Fr BE (32) + G1 (64) = 96 bytes.
    pub const MSM_TERM_WIRE_SIZE: usize = 32 + 64;

    /// Canonical byte representation. Returns `InvalidStageState` if
    /// `msm_terms.len()` exceeds the cap.
    pub fn serialize(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.msm_terms.len() > MAX_MSM_TERMS {
            return Err(Error::InvalidStageState);
        }

        out.extend_from_slice(STAGE2_STATE_MAGIC);
        out.extend_from_slice(&STAGE2_STATE_VERSION.to_le_bytes());

        // msm_terms: u32 LE count, then n × { Fr 32 | G1 64 }.
        out.extend_from_slice(&(self.msm_terms.len() as u32).to_le_bytes());
        for (scalar, point) in &self.msm_terms {
            out.extend_from_slice(&fr_to_bytes_be(scalar));
            out.extend_from_slice(&point.0);
        }

        // SHPLONK opening h2 + KZG VK G2 fields.
        out.extend_from_slice(&self.opening_proof_w_prime.0);
        out.extend_from_slice(&self.kzg_g2_one.0);
        out.extend_from_slice(&self.kzg_g2_tau.0);

        // Replay-binding + authority.
        out.extend_from_slice(&self.vk_hash);
        out.extend_from_slice(&self.proof_hash);
        out.extend_from_slice(&self.instance_hash);
        out.extend_from_slice(&self.payer);
        out.extend_from_slice(&self.nonce.to_le_bytes());

        Ok(())
    }

    /// Inverse of `serialize`. Strict: any trailing bytes, wrong magic /
    /// version, or count > cap → `InvalidStageState`.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut cur = 0usize;

        let magic = read_array::<8>(bytes, &mut cur)?;
        if &magic != STAGE2_STATE_MAGIC {
            return Err(Error::InvalidStageState);
        }
        let version = read_u32_le(bytes, &mut cur)?;
        if version != STAGE2_STATE_VERSION {
            return Err(Error::InvalidStageState);
        }

        let n_t = read_u32_le(bytes, &mut cur)? as usize;
        if n_t > MAX_MSM_TERMS {
            return Err(Error::InvalidStageState);
        }
        let mut msm_terms = Vec::with_capacity(n_t);
        for _ in 0..n_t {
            let scalar = read_fr(bytes, &mut cur)?;
            let point = G1(read_array::<64>(bytes, &mut cur)?);
            msm_terms.push((scalar, point));
        }

        let opening_proof_w_prime = G1(read_array::<64>(bytes, &mut cur)?);
        let kzg_g2_one = G2(read_array::<128>(bytes, &mut cur)?);
        let kzg_g2_tau = G2(read_array::<128>(bytes, &mut cur)?);

        let vk_hash = read_array::<32>(bytes, &mut cur)?;
        let proof_hash = read_array::<32>(bytes, &mut cur)?;
        let instance_hash = read_array::<32>(bytes, &mut cur)?;
        let payer = read_array::<32>(bytes, &mut cur)?;
        let nonce_bytes = read_array::<8>(bytes, &mut cur)?;
        let nonce = u64::from_le_bytes(nonce_bytes);

        if cur != bytes.len() {
            return Err(Error::InvalidStageState);
        }

        Ok(Stage2Output {
            msm_terms,
            opening_proof_w_prime,
            kzg_g2_one, kzg_g2_tau,
            vk_hash, proof_hash, instance_hash,
            payer, nonce,
        })
    }

    /// Number of bytes the canonical serialization will produce.
    pub fn serialized_size(&self) -> usize {
        const FIXED: usize =
              8                 // magic
            + 4                 // version
            + 4                 // msm_terms count
            + 64                // opening_proof_w_prime
            + 128 + 128         // kzg_g2_one + kzg_g2_tau
            + 32 + 32 + 32      // 3 replay hashes
            + 32                // payer
            + 8;                // nonce
        FIXED + Self::MSM_TERM_WIRE_SIZE * self.msm_terms.len()
    }
}

/// Compute the three replay-binding hashes for a verify input. Stage1
/// stores these in the PDA; stage2 re-runs this on the same data
/// account and compares.
pub fn compute_replay_hashes(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs: &[[u8; 32]],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let vk_hash = crate::syscalls::keccak256(vk_bytes);
    let proof_hash = crate::syscalls::keccak256(proof_bytes);

    // Concatenate public inputs (32 B each, BE) and hash.
    let mut pi_flat: Vec<u8> = Vec::with_capacity(public_inputs.len() * 32);
    for pi in public_inputs {
        pi_flat.extend_from_slice(pi);
    }
    let instance_hash = crate::syscalls::keccak256(&pi_flat);

    (vk_hash, proof_hash, instance_hash)
}

// ---------------------------------------------------------------------------
// byte-reader helpers (private)
// ---------------------------------------------------------------------------

fn read_u32_le(bytes: &[u8], cur: &mut usize) -> Result<u32, Error> {
    let arr = read_array::<4>(bytes, cur)?;
    Ok(u32::from_le_bytes(arr))
}

fn read_fr(bytes: &[u8], cur: &mut usize) -> Result<Fr, Error> {
    let arr = read_array::<32>(bytes, cur)?;
    fr_from_bytes_be(&arr)
}

fn read_array<const N: usize>(bytes: &[u8], cur: &mut usize) -> Result<[u8; N], Error> {
    if cur.checked_add(N).map_or(true, |e| e > bytes.len()) {
        return Err(Error::InvalidStageState);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*cur..*cur + N]);
    *cur += N;
    Ok(out)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;

    fn fr_n(n: u64) -> Fr {
        Fr::from(n)
    }

    fn synth() -> Stage1Output {
        Stage1Output {
            theta: fr_n(1),
            beta: fr_n(2),
            gamma: fr_n(3),
            y: fr_n(4),
            x: fr_n(5),
            shplonk_y: fr_n(6),
            shplonk_v: fr_n(7),
            shplonk_u: fr_n(8),
            user_challenges: alloc::vec![fr_n(99), fr_n(100)],
            l_0: fr_n(11),
            l_last: fr_n(12),
            l_blind: fr_n(13),
            xn: fr_n(14),
            expected_h_eval: fr_n(15),
            h_commitment: G1([0xAB; 64]),
            omega_last: fr_n(16),
            instance_evals: alloc::vec![fr_n(77)],
            vk_hash: [1u8; 32],
            proof_hash: [2u8; 32],
            instance_hash: [3u8; 32],
            payer: [0xCC; 32],
            nonce: 0x1122_3344_5566_7788,
        }
    }

    /// Round-trip a fully-populated state — every field byte-equal after
    /// serialize → deserialize.
    #[test]
    fn roundtrip_full() {
        let original = synth();
        let mut bytes = Vec::new();
        original.serialize(&mut bytes).unwrap();
        let restored = Stage1Output::deserialize(&bytes).unwrap();

        assert_eq!(restored.theta, original.theta);
        assert_eq!(restored.beta, original.beta);
        assert_eq!(restored.gamma, original.gamma);
        assert_eq!(restored.y, original.y);
        assert_eq!(restored.x, original.x);
        assert_eq!(restored.shplonk_y, original.shplonk_y);
        assert_eq!(restored.shplonk_v, original.shplonk_v);
        assert_eq!(restored.shplonk_u, original.shplonk_u);
        assert_eq!(restored.user_challenges, original.user_challenges);
        assert_eq!(restored.l_0, original.l_0);
        assert_eq!(restored.l_last, original.l_last);
        assert_eq!(restored.l_blind, original.l_blind);
        assert_eq!(restored.xn, original.xn);
        assert_eq!(restored.expected_h_eval, original.expected_h_eval);
        assert_eq!(restored.h_commitment.0, original.h_commitment.0);
        assert_eq!(restored.omega_last, original.omega_last);
        assert_eq!(restored.instance_evals, original.instance_evals);
        assert_eq!(restored.vk_hash, original.vk_hash);
        assert_eq!(restored.proof_hash, original.proof_hash);
        assert_eq!(restored.instance_hash, original.instance_hash);
        assert_eq!(restored.payer, original.payer);
        assert_eq!(restored.nonce, original.nonce);
    }

    /// Empty Vecs: no user_challenges, no instance_evals — the v1.5-shape
    /// case (StandardPlonk, Fibonacci).
    #[test]
    fn roundtrip_empty_vecs() {
        let original = Stage1Output {
            user_challenges: Vec::new(),
            instance_evals: Vec::new(),
            ..synth()
        };
        let mut bytes = Vec::new();
        original.serialize(&mut bytes).unwrap();
        let restored = Stage1Output::deserialize(&bytes).unwrap();
        assert!(restored.user_challenges.is_empty());
        assert!(restored.instance_evals.is_empty());
        assert_eq!(restored.theta, original.theta);
    }

    /// Serialized size matches `serialized_size()`.
    #[test]
    fn serialized_size_matches() {
        let original = synth();
        let mut bytes = Vec::new();
        original.serialize(&mut bytes).unwrap();
        assert_eq!(bytes.len(), original.serialized_size());
    }

    /// Wrong magic byte: deserialize must reject.
    #[test]
    fn wrong_magic_rejects() {
        let mut bytes = Vec::new();
        synth().serialize(&mut bytes).unwrap();
        bytes[0] = b'X';
        assert!(matches!(Stage1Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// Wrong version: deserialize must reject.
    #[test]
    fn wrong_version_rejects() {
        let mut bytes = Vec::new();
        synth().serialize(&mut bytes).unwrap();
        bytes[8..12].copy_from_slice(&999u32.to_le_bytes());
        assert!(matches!(Stage1Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// Trailing bytes: deserialize must reject (strict framing).
    #[test]
    fn trailing_bytes_rejects() {
        let mut bytes = Vec::new();
        synth().serialize(&mut bytes).unwrap();
        bytes.push(0xFF);
        assert!(matches!(Stage1Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// Truncated input: deserialize must reject.
    #[test]
    fn truncated_rejects() {
        let mut bytes = Vec::new();
        synth().serialize(&mut bytes).unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(matches!(Stage1Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// user_challenges count over MAX_USER_CHALLENGES: serialize must reject.
    #[test]
    fn oversized_user_challenges_rejects_serialize() {
        let mut s = synth();
        s.user_challenges = alloc::vec![Fr::ZERO; MAX_USER_CHALLENGES + 1];
        let mut bytes = Vec::new();
        assert!(matches!(s.serialize(&mut bytes), Err(Error::InvalidStageState)));
    }

    /// user_challenges count over MAX_USER_CHALLENGES on the wire:
    /// deserialize must reject (DoS bound).
    #[test]
    fn oversized_user_challenges_rejects_deserialize() {
        let mut bytes = Vec::new();
        synth().serialize(&mut bytes).unwrap();
        // Locate the user_challenges count u32 LE: just after magic (8) +
        // version (4) + 8 × 32 challenges = 268.
        let off = 8 + 4 + 8 * 32;
        bytes[off..off + 4].copy_from_slice(&((MAX_USER_CHALLENGES + 1) as u32).to_le_bytes());
        assert!(matches!(Stage1Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// Convenience accessors return the expected sub-structs.
    #[test]
    fn challenges_and_lagrange_accessors() {
        let s = synth();
        let ch = s.challenges();
        assert_eq!(ch.theta, s.theta);
        assert_eq!(ch.shplonk_u, s.shplonk_u);
        assert_eq!(ch.user_challenges, s.user_challenges);

        let lag = s.lagrange();
        assert_eq!(lag.l_0, s.l_0);
        assert_eq!(lag.xn, s.xn);
    }

    // ----- Stage2Output tests -----

    fn synth_term(seed: u8, scalar_val: u64) -> (Fr, G1) {
        (fr_n(scalar_val), G1([seed; 64]))
    }

    fn synth_stage2() -> Stage2Output {
        Stage2Output {
            msm_terms: alloc::vec![
                synth_term(1, 100),
                synth_term(2, 101),
                synth_term(3, 102),
            ],
            opening_proof_w_prime: G1([0xBB; 64]),
            kzg_g2_one: G2([0xDD; 128]),
            kzg_g2_tau: G2([0xEE; 128]),
            vk_hash: [1u8; 32],
            proof_hash: [2u8; 32],
            instance_hash: [3u8; 32],
            payer: [0xCC; 32],
            nonce: 0x99AA_BBCC_DDEE_FF00,
        }
    }

    /// Round-trip a fully-populated Stage2Output.
    #[test]
    fn stage2_roundtrip_full() {
        let original = synth_stage2();
        let mut bytes = Vec::new();
        original.serialize(&mut bytes).unwrap();
        let restored = Stage2Output::deserialize(&bytes).unwrap();

        assert_eq!(restored.msm_terms.len(), original.msm_terms.len());
        for (a, b) in restored.msm_terms.iter().zip(original.msm_terms.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1.0, b.1.0);
        }
        assert_eq!(restored.opening_proof_w_prime.0, original.opening_proof_w_prime.0);
        assert_eq!(restored.kzg_g2_one.0, original.kzg_g2_one.0);
        assert_eq!(restored.kzg_g2_tau.0, original.kzg_g2_tau.0);
        assert_eq!(restored.vk_hash, original.vk_hash);
        assert_eq!(restored.proof_hash, original.proof_hash);
        assert_eq!(restored.instance_hash, original.instance_hash);
        assert_eq!(restored.payer, original.payer);
        assert_eq!(restored.nonce, original.nonce);
    }

    /// Empty msm_terms roundtrip (degenerate but byte-format must still work).
    #[test]
    fn stage2_roundtrip_no_terms() {
        let original = Stage2Output { msm_terms: Vec::new(), ..synth_stage2() };
        let mut bytes = Vec::new();
        original.serialize(&mut bytes).unwrap();
        let restored = Stage2Output::deserialize(&bytes).unwrap();
        assert!(restored.msm_terms.is_empty());
        assert_eq!(restored.nonce, original.nonce);
    }

    /// `serialized_size()` matches the buffer `serialize()` produces.
    #[test]
    fn stage2_serialized_size_matches() {
        let original = synth_stage2();
        let mut bytes = Vec::new();
        original.serialize(&mut bytes).unwrap();
        assert_eq!(bytes.len(), original.serialized_size());
    }

    /// Wrong magic byte: deserialize must reject.
    #[test]
    fn stage2_wrong_magic_rejects() {
        let mut bytes = Vec::new();
        synth_stage2().serialize(&mut bytes).unwrap();
        bytes[0] = b'X';
        assert!(matches!(Stage2Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// Wrong version: deserialize must reject.
    #[test]
    fn stage2_wrong_version_rejects() {
        let mut bytes = Vec::new();
        synth_stage2().serialize(&mut bytes).unwrap();
        bytes[8..12].copy_from_slice(&999u32.to_le_bytes());
        assert!(matches!(Stage2Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// Trailing bytes: deserialize must reject.
    #[test]
    fn stage2_trailing_bytes_rejects() {
        let mut bytes = Vec::new();
        synth_stage2().serialize(&mut bytes).unwrap();
        bytes.push(0xFF);
        assert!(matches!(Stage2Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// Truncated input: deserialize must reject.
    #[test]
    fn stage2_truncated_rejects() {
        let mut bytes = Vec::new();
        synth_stage2().serialize(&mut bytes).unwrap();
        bytes.truncate(bytes.len() - 1);
        assert!(matches!(Stage2Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// msm_terms count over MAX_MSM_TERMS: serialize must reject.
    #[test]
    fn stage2_oversized_terms_rejects_serialize() {
        let mut s = synth_stage2();
        s.msm_terms = (0..(MAX_MSM_TERMS + 1)).map(|i| synth_term(0, i as u64)).collect();
        let mut bytes = Vec::new();
        assert!(matches!(s.serialize(&mut bytes), Err(Error::InvalidStageState)));
    }

    /// msm_terms count over MAX_MSM_TERMS on the wire: deserialize rejects (DoS bound).
    #[test]
    fn stage2_oversized_terms_rejects_deserialize() {
        let mut bytes = Vec::new();
        synth_stage2().serialize(&mut bytes).unwrap();
        // msm_terms count u32 LE is just after magic (8) + version (4).
        let off = 8 + 4;
        bytes[off..off + 4].copy_from_slice(&((MAX_MSM_TERMS + 1) as u32).to_le_bytes());
        assert!(matches!(Stage2Output::deserialize(&bytes), Err(Error::InvalidStageState)));
    }

    /// `compute_replay_hashes` is deterministic and distinct per input.
    #[test]
    fn replay_hashes_deterministic_and_distinct() {
        let vk = b"vk-bytes-A";
        let proof = b"proof-bytes-A";
        let pis: [[u8; 32]; 1] = [[7u8; 32]];

        let (a, b, c) = compute_replay_hashes(vk, proof, &pis);
        let (a2, b2, c2) = compute_replay_hashes(vk, proof, &pis);
        assert_eq!((a, b, c), (a2, b2, c2));

        let (a3, _, _) = compute_replay_hashes(b"vk-bytes-B", proof, &pis);
        assert_ne!(a, a3, "different vk → different vk_hash");
    }
}
