//! Protocol-order reader: parses proof bytes while interleaving Fiat–Shamir
//! squeezes. This is the part of the verifier that produces both the
//! `PlonkProof` and the `Challenges` consumed by gate / permutation / KZG
//! sub-arguments.
//!
//! Read order matches PSE-Halo2's `verify_proof` exactly (single-proof,
//! no-lookup, no-shuffle path):
//!
//! ```text
//!  ── absorb VK transcript_repr (already done at Keccak256Transcript::new)
//!  ── absorb public inputs                       (caller provides instances)
//!  R: advice commits                              [num_advice]   G1
//!  S: theta
//!  S: beta
//!  S: gamma
//!  R: permutation product commits                 [num_perm_chunks] G1
//!  R: random_poly commit                          [1]            G1
//!  S: y
//!  R: vanishing h pieces                          [cs_degree-1]  G1
//!  S: x
//!  R: advice evaluations                          [num_advice_queries] Fr
//!  R: fixed evaluations                           [num_fixed_queries]  Fr
//!  R: random_poly eval                            [1] Fr
//!  R: permutation common evals                    [num_perm_columns] Fr
//!  R: permutation product evals                   [num_perm_chunks*3] Fr (z, zω, z_last)
//!  R: opening proof W                             [1] G1
//!  R: opening proof W'                            [1] G1
//! ```
//!
//! `R:` = read from proof bytes + absorb into transcript.
//! `S:` = squeeze challenge.

use alloc::vec::Vec;
use ark_bn254::Fr;

use crate::{
    plonk::{Challenges, PlonkProof, PlonkProtocol},
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

    // squeeze theta, beta, gamma ───────────────────────────────────────────
    let theta = transcript.squeeze_challenge();
    let beta  = transcript.squeeze_challenge();
    let gamma = transcript.squeeze_challenge();

    // (2) permutation product commits ──────────────────────────────────────
    let permutation_product_commits =
        read_g1s(transcript, proof_bytes, &mut cur, vk.num_perm_chunks)?;

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
            opening_proof_w,
            opening_proof_w_prime,
        },
        Challenges { theta, beta, gamma, y, x, shplonk_y, shplonk_v, shplonk_u },
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
      + vk.num_perm_chunks                  // perm product commits
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
      + perm_prod_evals;

    g1_count * G1_LEN + fr_count * FR_LEN
}

#[cfg(all(test, feature = "std", feature = "solana-syscalls"))]
mod tests {
    use super::*;
    use crate::curve::G1;
    use crate::field::fr_to_bytes_be;

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
            transcript_repr: [0u8; 32],
        }
    }

    fn synth_g1(tag: u8) -> [u8; 64] {
        // Identity if tag=0; otherwise (tag, tag+1) which is on-curve only if
        // we're lucky. For pure byte-level read tests we don't need on-curve
        // points — read_g1 doesn't validate.
        let mut b = [0u8; 64];
        if tag != 0 { b[31] = tag; b[63] = tag.wrapping_add(1); }
        b
    }

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
            transcript_repr: [0u8; 32],
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
            transcript_repr: [0u8; 32],
        };
        // G1 = 3 advice + 1 perm + 1 random + 3 h + 2 W = 10 → 640 B
        // Fr = 3 advice_evals + 5 fixed_evals + 1 random_eval
        //    + 3 perm_common + (3·0+2)=2 perm-product = 14 → 448 B
        // total 1088
        assert_eq!(expected_proof_size(&vk), 1088);
    }
}
