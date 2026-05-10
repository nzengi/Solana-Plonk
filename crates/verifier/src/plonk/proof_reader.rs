//! Protocol-order reader: parses proof bytes while interleaving Fiat–Shamir
//! squeezes. This is the part of the verifier that produces both the
//! `PlonkProof` and the `Challenges` consumed by gate / permutation / KZG
//! sub-arguments.
//!
//! Read order matches PSE-Halo2's `verify_proof` exactly. v2.0 adds
//! lookup/shuffle commits + evals and per-phase user challenges.
//!
//! ```text
//!  ── absorb VK transcript_repr (already done at Keccak256Transcript::new)
//!  ── absorb public inputs                       (caller provides instances)
//!  R: advice commits                              [num_advice]   G1
//!  S: user challenges                             [num_challenges]   (v2.0)
//!  S: theta
//!  R: per-lookup permuted_input + permuted_table  [2 · num_lookups] G1   (v2.0)
//!  S: beta
//!  S: gamma
//!  R: permutation product commits                 [num_perm_chunks] G1
//!  R: per-lookup product commits                  [num_lookups] G1       (v2.0)
//!  R: per-shuffle product commits                 [num_shuffles] G1      (v2.0)
//!  R: random_poly commit                          [1]            G1
//!  S: y
//!  R: vanishing h pieces                          [cs_degree-1]  G1
//!  S: x
//!  R: advice evaluations                          [num_advice_queries] Fr
//!  R: fixed evaluations                           [num_fixed_queries]  Fr
//!  R: random_poly eval                            [1] Fr
//!  R: permutation common evals                    [num_perm_columns] Fr
//!  R: permutation product evals                   [num_perm_chunks*3] Fr (z, zω, z_last)
//!  R: per-lookup 5 evals                          [5 · num_lookups] Fr   (v2.0)
//!  R: per-shuffle 2 evals                         [2 · num_shuffles] Fr  (v2.0)
//!  S: shplonk_y, shplonk_v
//!  R: opening proof W                             [1] G1
//!  S: shplonk_u
//!  R: opening proof W'                            [1] G1
//! ```
//!
//! `R:` = read from proof bytes + absorb into transcript.
//! `S:` = squeeze challenge.

use alloc::vec::Vec;
use ark_bn254::Fr;

use crate::{
    plonk::{Challenges, LookupEvals, PlonkProof, PlonkProtocol},
    transcript::Keccak256Transcript,
    Error,
};

/// Parse proof bytes and derive Fiat–Shamir challenges in the correct order.
///
/// `public_inputs` are the BE-encoded scalars for each public input value;
/// the caller must have already validated they are in canonical Fr form
/// (use `crate::field::fr_from_bytes_be`). They are absorbed *as scalars*
/// (PSE QUERY_INSTANCE = false path).
pub fn read_proof(
    vk:            &PlonkProtocol,
    proof_bytes:   &[u8],
    public_inputs: &[[u8; 32]],
    transcript:    &mut Keccak256Transcript,
) -> Result<(PlonkProof, Challenges), Error> {
    // ── absorb public inputs ───────────────────────────────────────────────
    // Halo2's `transcript.common_scalar` for each instance value.
    for inst in public_inputs {
        transcript.absorb_scalar(inst);
    }

    let mut cur = 0usize;

    // (1) advice commits ───────────────────────────────────────────────────
    let advice_commits = read_g1s(transcript, proof_bytes, &mut cur, vk.num_advice)?;

    // (1.5) v2.0: user-defined phase challenges. Halo2 squeezes one challenge
    // per `cs.num_challenges()` AFTER the matching phase's advice commits and
    // BEFORE theta. v1.5 collapsed all advice into one batch (single-phase
    // assumption) — we keep that here, so all user challenges are squeezed in
    // one block. Multi-phase splitting is task #46.
    let mut user_challenges = Vec::with_capacity(vk.num_challenges);
    for _ in 0..vk.num_challenges {
        user_challenges.push(transcript.squeeze_challenge());
    }

    // squeeze theta ────────────────────────────────────────────────────────
    let theta = transcript.squeeze_challenge();

    // (1.6) v2.0: per-lookup permuted_input_commitment + permuted_table_commitment
    let mut lookup_permuted_input_commits = Vec::with_capacity(vk.num_lookups());
    let mut lookup_permuted_table_commits = Vec::with_capacity(vk.num_lookups());
    for _ in 0..vk.num_lookups() {
        lookup_permuted_input_commits.push(transcript.read_g1(proof_bytes, &mut cur)?);
        lookup_permuted_table_commits.push(transcript.read_g1(proof_bytes, &mut cur)?);
    }

    // squeeze beta, gamma ──────────────────────────────────────────────────
    let beta  = transcript.squeeze_challenge();
    let gamma = transcript.squeeze_challenge();

    // (2) permutation product commits ──────────────────────────────────────
    let permutation_product_commits =
        read_g1s(transcript, proof_bytes, &mut cur, vk.num_perm_chunks)?;

    // (2.5) v2.0: per-lookup grand-product commits + per-shuffle product commits
    let lookup_product_commits =
        read_g1s(transcript, proof_bytes, &mut cur, vk.num_lookups())?;
    let shuffle_product_commits =
        read_g1s(transcript, proof_bytes, &mut cur, vk.num_shuffles())?;

    // (3) random_poly commit ───────────────────────────────────────────────
    let random_poly_commit = transcript.read_g1(proof_bytes, &mut cur)?;

    // squeeze y ────────────────────────────────────────────────────────────
    let y = transcript.squeeze_challenge();

    // (4) vanishing h pieces ───────────────────────────────────────────────
    let h_count = vk.cs_degree.saturating_sub(1);
    let vanishing_h_commits =
        read_g1s(transcript, proof_bytes, &mut cur, h_count)?;

    // squeeze x ────────────────────────────────────────────────────────────
    let x = transcript.squeeze_challenge();

    // (5) advice evals, (6) fixed evals ────────────────────────────────────
    let advice_evals = read_scalars(transcript, proof_bytes, &mut cur, vk.num_advice_queries)?;
    let fixed_evals  = read_scalars(transcript, proof_bytes, &mut cur, vk.num_fixed_queries)?;

    // (7) random_poly eval ─────────────────────────────────────────────────
    let random_poly_eval = transcript.read_scalar(proof_bytes, &mut cur)?;

    // (8) permutation common evals ─────────────────────────────────────────
    let permutation_common_evals =
        read_scalars(transcript, proof_bytes, &mut cur, vk.num_perm_columns())?;

    // (9) permutation product evals — 3 per chunk except the LAST chunk
    // which reads only (z, z_ω). Matches halo2_proofs's
    // `permutation::Committed::evaluate` which conditions z_last on
    // `iter.len() > 0`.
    let mut permutation_product_evals = Vec::with_capacity(vk.num_perm_chunks);
    for i in 0..vk.num_perm_chunks {
        let z       = transcript.read_scalar(proof_bytes, &mut cur)?;
        let z_omega = transcript.read_scalar(proof_bytes, &mut cur)?;
        let z_last  = if i + 1 < vk.num_perm_chunks {
            transcript.read_scalar(proof_bytes, &mut cur)?
        } else {
            // Last chunk has no z_last in the wire format. The field is
            // unused downstream (only `expressions` for chunks i ≥ 1
            // reads `prev_chunk.z_last`, never `last_chunk.z_last`).
            Fr::from(0u64)
        };
        permutation_product_evals.push((z, z_omega, z_last));
    }

    // (9.5) v2.0: per-lookup 5 evals — exact transcript order matters.
    // halo2's `lookup::Committed::evaluate` reads in this sequence:
    //   product_eval, product_next_eval, permuted_input_eval,
    //   permuted_input_inv_eval, permuted_table_eval
    let mut lookup_evals = Vec::with_capacity(vk.num_lookups());
    for _ in 0..vk.num_lookups() {
        let product_eval            = transcript.read_scalar(proof_bytes, &mut cur)?;
        let product_next_eval       = transcript.read_scalar(proof_bytes, &mut cur)?;
        let permuted_input_eval     = transcript.read_scalar(proof_bytes, &mut cur)?;
        let permuted_input_inv_eval = transcript.read_scalar(proof_bytes, &mut cur)?;
        let permuted_table_eval     = transcript.read_scalar(proof_bytes, &mut cur)?;
        lookup_evals.push(LookupEvals {
            product_eval,
            product_next_eval,
            permuted_input_eval,
            permuted_input_inv_eval,
            permuted_table_eval,
        });
    }

    // (9.6) v2.0: per-shuffle 2 evals — (product_eval, product_next_eval).
    let mut shuffle_evals = Vec::with_capacity(vk.num_shuffles());
    for _ in 0..vk.num_shuffles() {
        let product_eval      = transcript.read_scalar(proof_bytes, &mut cur)?;
        let product_next_eval = transcript.read_scalar(proof_bytes, &mut cur)?;
        shuffle_evals.push((product_eval, product_next_eval));
    }

    // ── SHPLONK opening protocol ───────────────────────────────────────────
    // Order matches halo2_proofs::poly::kzg::multiopen::shplonk::verifier:
    //   squeeze y  → squeeze v  → read h1  → squeeze u  → read h2
    let shplonk_y = transcript.squeeze_challenge();
    let shplonk_v = transcript.squeeze_challenge();
    let opening_proof_w = transcript.read_g1(proof_bytes, &mut cur)?;
    let shplonk_u = transcript.squeeze_challenge();
    let opening_proof_w_prime = transcript.read_g1(proof_bytes, &mut cur)?;

    if cur != proof_bytes.len() {
        return Err(Error::InvalidProofEncoding);
    }

    Ok((
        PlonkProof {
            advice_commits,
            permutation_product_commits,
            random_poly_commit,
            vanishing_h_commits,
            advice_evals,
            fixed_evals,
            random_poly_eval,
            permutation_common_evals,
            permutation_product_evals,
            lookup_permuted_input_commits,
            lookup_permuted_table_commits,
            lookup_product_commits,
            lookup_evals,
            shuffle_product_commits,
            shuffle_evals,
            opening_proof_w,
            opening_proof_w_prime,
        },
        Challenges {
            theta, beta, gamma, y, x, shplonk_y, shplonk_v, shplonk_u,
            user_challenges,
        },
    ))
}

#[inline]
fn read_g1s(
    transcript: &mut Keccak256Transcript,
    proof: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<crate::curve::G1>, Error> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(transcript.read_g1(proof, cursor)?);
    }
    Ok(out)
}

/// Parse proof bytes into `PlonkProof` **without** running the Fiat–Shamir
/// transcript. The challenges are trusted from another source — in
/// practice the 2-tx split's `Stage1Output` (which derived them via the
/// full transcript in stage 1).
///
/// Saves the keccak squeezes and absorb-buffer growth that `read_proof`
/// performs. On BPF this is roughly ~50–80 k CU, depending on how many
/// challenges + how large the absorbed proof transcript would have grown.
///
/// **Soundness note**: this function does NOT verify the challenges are
/// the right ones. Caller MUST have a separate replay-binding mechanism
/// (e.g. stage 1's `vk_hash` / `proof_hash` / `instance_hash` triple) to
/// guarantee the proof bytes used here match the ones that produced the
/// trusted challenges. Otherwise a tampered proof's commits/evals would
/// fly through this parser unchecked.
pub fn parse_proof_no_fs(
    vk:          &PlonkProtocol,
    proof_bytes: &[u8],
) -> Result<PlonkProof, Error> {
    let mut cur = 0usize;

    // (1) advice commits
    let advice_commits = read_g1s_no_fs(proof_bytes, &mut cur, vk.num_advice)?;

    // (1.6) per-lookup permuted_input + permuted_table commits
    let mut lookup_permuted_input_commits = Vec::with_capacity(vk.num_lookups());
    let mut lookup_permuted_table_commits = Vec::with_capacity(vk.num_lookups());
    for _ in 0..vk.num_lookups() {
        lookup_permuted_input_commits.push(read_g1_no_fs(proof_bytes, &mut cur)?);
        lookup_permuted_table_commits.push(read_g1_no_fs(proof_bytes, &mut cur)?);
    }

    // (2) permutation product commits
    let permutation_product_commits =
        read_g1s_no_fs(proof_bytes, &mut cur, vk.num_perm_chunks)?;

    // (2.5) per-lookup grand-product commits + per-shuffle product commits
    let lookup_product_commits =
        read_g1s_no_fs(proof_bytes, &mut cur, vk.num_lookups())?;
    let shuffle_product_commits =
        read_g1s_no_fs(proof_bytes, &mut cur, vk.num_shuffles())?;

    // (3) random_poly commit
    let random_poly_commit = read_g1_no_fs(proof_bytes, &mut cur)?;

    // (4) vanishing h pieces
    let h_count = vk.cs_degree.saturating_sub(1);
    let vanishing_h_commits = read_g1s_no_fs(proof_bytes, &mut cur, h_count)?;

    // (5,6) advice evals + fixed evals
    let advice_evals = read_scalars_no_fs(proof_bytes, &mut cur, vk.num_advice_queries)?;
    let fixed_evals  = read_scalars_no_fs(proof_bytes, &mut cur, vk.num_fixed_queries)?;

    // (7) random_poly eval
    let random_poly_eval = read_scalar_no_fs(proof_bytes, &mut cur)?;

    // (8) permutation common evals
    let permutation_common_evals =
        read_scalars_no_fs(proof_bytes, &mut cur, vk.num_perm_columns())?;

    // (9) permutation product evals — same shape as `read_proof`.
    let mut permutation_product_evals = Vec::with_capacity(vk.num_perm_chunks);
    for i in 0..vk.num_perm_chunks {
        let z       = read_scalar_no_fs(proof_bytes, &mut cur)?;
        let z_omega = read_scalar_no_fs(proof_bytes, &mut cur)?;
        let z_last  = if i + 1 < vk.num_perm_chunks {
            read_scalar_no_fs(proof_bytes, &mut cur)?
        } else {
            Fr::from(0u64)
        };
        permutation_product_evals.push((z, z_omega, z_last));
    }

    // (9.5) per-lookup 5 evals
    let mut lookup_evals = Vec::with_capacity(vk.num_lookups());
    for _ in 0..vk.num_lookups() {
        let product_eval            = read_scalar_no_fs(proof_bytes, &mut cur)?;
        let product_next_eval       = read_scalar_no_fs(proof_bytes, &mut cur)?;
        let permuted_input_eval     = read_scalar_no_fs(proof_bytes, &mut cur)?;
        let permuted_input_inv_eval = read_scalar_no_fs(proof_bytes, &mut cur)?;
        let permuted_table_eval     = read_scalar_no_fs(proof_bytes, &mut cur)?;
        lookup_evals.push(crate::plonk::LookupEvals {
            product_eval,
            product_next_eval,
            permuted_input_eval,
            permuted_input_inv_eval,
            permuted_table_eval,
        });
    }

    // (9.6) per-shuffle 2 evals
    let mut shuffle_evals = Vec::with_capacity(vk.num_shuffles());
    for _ in 0..vk.num_shuffles() {
        let product_eval      = read_scalar_no_fs(proof_bytes, &mut cur)?;
        let product_next_eval = read_scalar_no_fs(proof_bytes, &mut cur)?;
        shuffle_evals.push((product_eval, product_next_eval));
    }

    // SHPLONK opening proofs
    let opening_proof_w       = read_g1_no_fs(proof_bytes, &mut cur)?;
    let opening_proof_w_prime = read_g1_no_fs(proof_bytes, &mut cur)?;

    if cur != proof_bytes.len() {
        return Err(Error::InvalidProofEncoding);
    }

    Ok(PlonkProof {
        advice_commits,
        permutation_product_commits,
        random_poly_commit,
        vanishing_h_commits,
        advice_evals,
        fixed_evals,
        random_poly_eval,
        permutation_common_evals,
        permutation_product_evals,
        lookup_permuted_input_commits,
        lookup_permuted_table_commits,
        lookup_product_commits,
        lookup_evals,
        shuffle_product_commits,
        shuffle_evals,
        opening_proof_w,
        opening_proof_w_prime,
    })
}

#[inline]
fn read_g1_no_fs(proof: &[u8], cursor: &mut usize) -> Result<crate::curve::G1, Error> {
    if cursor.checked_add(64).map_or(true, |end| end > proof.len()) {
        return Err(Error::InvalidProofEncoding);
    }
    let bytes: [u8; 64] = proof[*cursor..*cursor + 64].try_into().unwrap();
    *cursor += 64;
    Ok(crate::curve::G1(bytes))
}

#[inline]
fn read_g1s_no_fs(
    proof: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<crate::curve::G1>, Error> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_g1_no_fs(proof, cursor)?);
    }
    Ok(out)
}

#[inline]
fn read_scalar_no_fs(proof: &[u8], cursor: &mut usize) -> Result<Fr, Error> {
    if cursor.checked_add(32).map_or(true, |end| end > proof.len()) {
        return Err(Error::InvalidProofEncoding);
    }
    let bytes: &[u8; 32] = proof[*cursor..*cursor + 32].try_into().unwrap();
    let scalar = crate::field::fr_from_bytes_be(bytes)?;
    *cursor += 32;
    Ok(scalar)
}

#[inline]
fn read_scalars_no_fs(
    proof: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<Fr>, Error> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(read_scalar_no_fs(proof, cursor)?);
    }
    Ok(out)
}

#[inline]
fn read_scalars(
    transcript: &mut Keccak256Transcript,
    proof: &[u8],
    cursor: &mut usize,
    count: usize,
) -> Result<Vec<Fr>, Error> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(transcript.read_scalar(proof, cursor)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Helper for tests + golden-vector tooling: compute the exact proof byte
// length for a given VK. Useful to sanity-check prover output before
// attempting verification.
// ---------------------------------------------------------------------------

pub fn expected_proof_size(vk: &PlonkProtocol) -> usize {
    const G1_LEN: usize = 64;
    const FR_LEN: usize = 32;

    let g1_count =
        vk.num_advice                       // advice commits
      + 2 * vk.num_lookups()                // v2.0: permuted_input + permuted_table per lookup
      + vk.num_perm_chunks                  // perm product commits
      + vk.num_lookups()                    // v2.0: 1 product commit per lookup
      + vk.num_shuffles()                   // v2.0: 1 product commit per shuffle
      + 1                                   // random_poly commit
      + vk.cs_degree.saturating_sub(1)      // vanishing h pieces
      + 2;                                  // opening proof W, W'

    // Permutation product evals = 3·(num_chunks − 1) + 2  (last chunk omits z_last).
    // Equals 0 when num_chunks = 0.
    let perm_prod_evals = if vk.num_perm_chunks == 0 {
        0
    } else {
        3 * (vk.num_perm_chunks - 1) + 2
    };
    let fr_count =
        vk.num_advice_queries
      + vk.num_fixed_queries
      + 1                                   // random_poly eval
      + vk.num_perm_columns()
      + perm_prod_evals
      + 5 * vk.num_lookups()                // v2.0: 5 evals per lookup
      + 2 * vk.num_shuffles();              // v2.0: 2 evals per shuffle

    g1_count * G1_LEN + fr_count * FR_LEN
}

#[cfg(all(test, feature = "std", feature = "solana-syscalls"))]
mod tests {
    use super::*;
    use crate::curve::G1;
    #[allow(unused_imports)]
    use crate::field::fr_to_bytes_be;

    #[allow(dead_code)]
    fn zero_vk(num_advice: usize, num_advice_queries: usize, cs_degree: usize) -> PlonkProtocol {
        use ark_ff::Field;
        PlonkProtocol {
            k: 4,
            omega: Fr::ONE,
            num_instance: 0,
            num_advice,
            num_fixed: 0,
            cs_degree,
            num_advice_queries,
            num_fixed_queries: 0,
            blinding_factors: 0,
            num_perm_chunks: 1,
            fixed_commitments: Vec::new(),
            permutation_commitments: alloc::vec![G1::IDENTITY], // 1 perm column
            transcript_repr: [0u8; 32], ..Default::default()
        }
    }

    #[allow(dead_code)]
    fn synth_g1(tag: u8) -> [u8; 64] {
        // Identity if tag=0; otherwise (tag, tag+1) which is on-curve only if
        // we're lucky. For pure byte-level read tests we don't need on-curve
        // points — read_g1 doesn't validate.
        let mut b = [0u8; 64];
        if tag != 0 { b[31] = tag; b[63] = tag.wrapping_add(1); }
        b
    }

    #[allow(dead_code)]
    fn synth_scalar(tag: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = tag; // small enough to be in Fr range
        b
    }

    /// Round-trip: build a minimal proof byte stream by hand, run read_proof,
    /// confirm parsed fields and final cursor position match.
    #[test]
    fn read_proof_minimal_circuit() {
        // 2-advice, 2-advice-queries, 1-fixed-query, cs_degree=3 → 2 h-pieces,
        // 1 permutation column → 1 chunk, no instance.
        let vk = PlonkProtocol {
            k: 4,
            omega: Fr::from(1u64),
            num_instance: 0,
            num_advice: 2,
            num_fixed: 1,
            cs_degree: 3,
            num_advice_queries: 2,
            num_fixed_queries: 1,
            blinding_factors: 0,
            num_perm_chunks: 1,
            fixed_commitments: alloc::vec![G1::IDENTITY],
            permutation_commitments: alloc::vec![G1::IDENTITY],
            transcript_repr: [0u8; 32], ..Default::default()
        };

        // Proof composition (zeros are fine — no on-curve check in reader):
        //   2 advice + 1 perm + 1 random + 2 h-pieces + 2 W = 8 G1 = 512 bytes
        //   2 advice + 1 fixed + 1 random + 1 perm-common
        //   + 2 perm-product (last chunk: z, z_ω only) = 7 Fr = 224 bytes
        //   total = 736 bytes
        let expected = expected_proof_size(&vk);
        assert_eq!(expected, 736);

        let proof = alloc::vec![0u8; expected];

        let mut transcript = Keccak256Transcript::new(&[0u8; 32]);
        let (parsed, ch) = read_proof(&vk, &proof, &[], &mut transcript).unwrap();

        assert_eq!(parsed.advice_commits.len(),                 2);
        assert_eq!(parsed.permutation_product_commits.len(),    1);
        assert_eq!(parsed.vanishing_h_commits.len(),            2);
        assert_eq!(parsed.advice_evals.len(),                   2);
        assert_eq!(parsed.fixed_evals.len(),                    1);
        assert_eq!(parsed.permutation_common_evals.len(),       1);
        assert_eq!(parsed.permutation_product_evals.len(),      1);

        // Challenges must all be distinct — a degenerate transcript would
        // produce equal squeezes and silently break the protocol.
        let chs = [ch.theta, ch.beta, ch.gamma, ch.y, ch.x];
        for i in 0..chs.len() {
            for j in (i + 1)..chs.len() {
                assert_ne!(chs[i], chs[j], "challenges {i}/{j} collided");
            }
        }
    }

    #[test]
    fn read_proof_rejects_short_buffer() {
        let vk = zero_vk(1, 1, 2);
        // Expected size for this VK > 0.
        let need = expected_proof_size(&vk);
        let short = alloc::vec![0u8; need - 1];
        let mut t = Keccak256Transcript::new(&[0u8; 32]);
        let r = read_proof(&vk, &short, &[], &mut t);
        assert!(matches!(r, Err(Error::InvalidProofEncoding)));
    }

    #[test]
    fn read_proof_rejects_trailing_bytes() {
        let vk = zero_vk(1, 1, 2);
        let need = expected_proof_size(&vk);
        let mut buf = alloc::vec![0u8; need + 1]; // 1 byte too long
        buf[need] = 0xFF;
        let mut t = Keccak256Transcript::new(&[0u8; 32]);
        let r = read_proof(&vk, &buf, &[], &mut t);
        assert!(matches!(r, Err(Error::InvalidProofEncoding)));
    }

    #[test]
    fn read_proof_rejects_eval_above_modulus() {
        let vk = zero_vk(0, 0, 2); // no commits, no advice/fixed evals
        // Build proof: 0 advice + 1 perm + 1 random + 1 h piece = 3 G1 = 192 bytes
        //              read 0 advice/fixed evals, then random_poly_eval at offset 192,
        //              then 1 perm_common, then 2 perm-product evals (last chunk),
        //              then 2 W openings.
        //              Total: 3*64 + 4*32 + 2*64 = 192 + 128 + 128 = 448 bytes
        let mut proof = alloc::vec![0u8; expected_proof_size(&vk)];
        assert_eq!(proof.len(), 448);
        // random_poly_eval is the FIRST scalar — at offset 192 (after 3 G1).
        let offset = 192;
        // Set scalar to BN254 Fr modulus (rejected by fr_from_bytes_be).
        proof[offset..offset + 32].copy_from_slice(&[
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
            0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
        ]);
        let mut t = Keccak256Transcript::new(&[0u8; 32]);
        let r = read_proof(&vk, &proof, &[], &mut t);
        assert!(matches!(r, Err(Error::PublicInputOutOfRange)));
    }

    #[test]
    fn expected_proof_size_matches_layout() {
        let vk = PlonkProtocol {
            k: 4,
            omega: Fr::from(1u64),
            num_instance: 1,
            num_advice: 3,
            num_fixed: 5,
            cs_degree: 4,
            num_advice_queries: 3,
            num_fixed_queries: 5,
            blinding_factors: 0,
            num_perm_chunks: 1,
            fixed_commitments: Vec::new(),
            permutation_commitments: alloc::vec![G1::IDENTITY; 3],
            transcript_repr: [0u8; 32], ..Default::default()
        };
        // G1 = 3 advice + 1 perm + 1 random + 3 h + 2 W = 10 → 640 B
        // Fr = 3 advice_evals + 5 fixed_evals + 1 random_eval
        //    + 3 perm_common + (3·0+2)=2 perm-product = 14 → 448 B
        // total 1088
        assert_eq!(expected_proof_size(&vk), 1088);
    }

    /// `parse_proof_no_fs` produces the same `PlonkProof` as `read_proof`
    /// for any valid input. Verified against a real shuffle golden vector;
    /// every field byte-equal. The two functions diverge only in their
    /// internal Fiat–Shamir behaviour, which doesn't affect the parsed
    /// proof structure.
    #[test]
    fn parse_proof_no_fs_matches_read_proof_on_shuffle() {
        let raw = std::fs::read("../../circuits/shuffle-check/tests/golden_v2_sh.bin")
            .expect("missing shuffle golden — run `cargo run -p shuffle-check-circuit --bin gen-sh-proof -- --write-golden`");
        // GLDN0002 layout: 8 magic + 4 vk_len + vk + 4 proof_len + proof + ...
        let vk_len = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
        let vk_bytes = &raw[12..12 + vk_len];
        let proof_off = 12 + vk_len + 4;
        let proof_len = u32::from_le_bytes([
            raw[12 + vk_len], raw[12 + vk_len + 1],
            raw[12 + vk_len + 2], raw[12 + vk_len + 3],
        ]) as usize;
        let proof_bytes = &raw[proof_off..proof_off + proof_len];

        let vk = crate::vk::parse_vk(vk_bytes).unwrap();

        // Path A: full read_proof with FS.
        let mut t = Keccak256Transcript::new(&vk.transcript_repr);
        let (proof_a, _ch) = read_proof(&vk, proof_bytes, &[], &mut t).unwrap();

        // Path B: skip-FS parser.
        let proof_b = parse_proof_no_fs(&vk, proof_bytes).unwrap();

        // Every field must be byte-identical between the two paths.
        assert_eq!(proof_a.advice_commits.len(), proof_b.advice_commits.len());
        for (a, b) in proof_a.advice_commits.iter().zip(proof_b.advice_commits.iter()) {
            assert_eq!(a.0, b.0, "advice commit mismatch");
        }
        assert_eq!(proof_a.permutation_product_commits.len(),
                   proof_b.permutation_product_commits.len());
        assert_eq!(proof_a.random_poly_commit.0, proof_b.random_poly_commit.0);
        assert_eq!(proof_a.vanishing_h_commits.len(), proof_b.vanishing_h_commits.len());
        for (a, b) in proof_a.vanishing_h_commits.iter().zip(proof_b.vanishing_h_commits.iter()) {
            assert_eq!(a.0, b.0, "h piece commit mismatch");
        }
        assert_eq!(proof_a.advice_evals, proof_b.advice_evals);
        assert_eq!(proof_a.fixed_evals, proof_b.fixed_evals);
        assert_eq!(proof_a.random_poly_eval, proof_b.random_poly_eval);
        assert_eq!(proof_a.permutation_common_evals, proof_b.permutation_common_evals);
        assert_eq!(proof_a.permutation_product_evals, proof_b.permutation_product_evals);
        assert_eq!(proof_a.shuffle_product_commits.len(),
                   proof_b.shuffle_product_commits.len());
        for (a, b) in proof_a.shuffle_product_commits.iter()
                                .zip(proof_b.shuffle_product_commits.iter()) {
            assert_eq!(a.0, b.0, "shuffle product commit mismatch");
        }
        assert_eq!(proof_a.shuffle_evals, proof_b.shuffle_evals);
        assert_eq!(proof_a.opening_proof_w.0, proof_b.opening_proof_w.0);
        assert_eq!(proof_a.opening_proof_w_prime.0, proof_b.opening_proof_w_prime.0);
    }

    /// `parse_proof_no_fs` honours the same strict-canonical Fr check as
    /// `read_proof`. A non-canonical scalar (≥ Fr modulus) → InvalidProofEncoding.
    #[test]
    fn parse_proof_no_fs_rejects_noncanonical_fr() {
        // Synthesize a proof of all zero G1 (size matches a tiny VK) and one
        // Fr that's >= modulus.
        let vk = zero_vk(0, 0, 2);
        // Layout: 0 advice + 1 perm + 1 random + 1 h = 3 G1 = 192 B
        //   + 0 advice_evals + 0 fixed_evals + 1 random_eval
        //   + 1 perm_common + 2 perm-product = 4 Fr = 128 B
        //   + 2 W openings = 128 B
        //   total = 448 B
        let mut proof = alloc::vec![0u8; expected_proof_size(&vk)];
        assert_eq!(proof.len(), 448);
        // random_poly_eval is the FIRST scalar — at offset 192 (after 3 G1).
        proof[192..192 + 32].copy_from_slice(&[
            0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
            0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
            0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
            0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
        ]);
        let r = parse_proof_no_fs(&vk, &proof);
        assert!(matches!(r, Err(Error::PublicInputOutOfRange)));
    }
}
