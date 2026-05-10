//! PLONK copy-constraint (permutation) argument verification.
//!
//! Mirrors `halo2_proofs::plonk::permutation::verifier::Evaluated::expressions`.
//! Returns a `Vec<Fr>` of constraint contributions that the gate-mixing `y`
//! challenge later folds into the total expected `h(x) · (xⁿ − 1)` value.
//!
//! The four expression families (per halo2):
//!
//! ```text
//!   1. L_0(x) · (1 − z_first(x))             — first set initial
//!   2. L_last(x) · (z_last(x)² − z_last(x))  — last set final
//!   3. L_0(x) · (z_i(x) − z_{i-1}(ω^last·x)) — inter-set chain stitching
//!      (skipped for first set; not present when only one set)
//!   4. per-chunk grand-product step:
//!         (1 − L_last − L_blind) ·
//!            (z_i(ωx)·∏(eval + β·σ(x) + γ)  −  z_i(x)·∏(eval + δⁱ·β·x + γ))
//! ```
//!
//! v1 simplification: permuted columns are assumed to be advice columns
//! `[0..num_perm_columns)` (sufficient for StandardPlonk-style circuits).
//! Generalising to mixed advice/fixed/instance permutation is v1.5.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::Field;
#[cfg(test)] use ark_ff::AdditiveGroup;

use crate::{
    field,
    plonk::{Challenges, PlonkProof, PlonkProtocol},
    plonk::lagrange::LagrangeEvaluations,
    Error,
};

/// Compute the permutation argument's constraint contributions at challenge `x`.
///
/// `#[inline(never)]` keeps this large function out of the caller's BPF stack
/// frame — inlining into `verify()` pushes the combined frame past the
/// 4096-byte SBF limit.
#[inline(never)]
pub fn expressions(
    vk: &PlonkProtocol,
    proof: &PlonkProof,
    ch:    &Challenges,
    lag:   &LagrangeEvaluations,
) -> Result<Vec<Fr>, Error> {
    let chunk_len = vk.cs_degree.saturating_sub(2).max(1);
    let num_perm_cols = vk.num_perm_columns();

    if vk.num_perm_chunks == 0 {
        return Ok(Vec::new()); // no permutation — no contributions
    }
    if proof.permutation_product_evals.len() != vk.num_perm_chunks {
        return Err(Error::Protocol("perm: chunk count mismatch"));
    }
    if proof.permutation_common_evals.len() != num_perm_cols {
        return Err(Error::Protocol("perm: common eval count mismatch"));
    }
    // v1 assumption: permuted columns are advice[0..num_perm_cols].
    if num_perm_cols > vk.num_advice {
        return Err(Error::Protocol("perm: more perm cols than advice cols (v1.5 generalisation needed)"));
    }
    if proof.advice_evals.len() < num_perm_cols {
        return Err(Error::Protocol("perm: advice_evals shorter than num_perm_cols"));
    }

    let mut out: Vec<Fr> = Vec::new();

    // (1) L_0(x) · (1 − z_0(x)) — first set initial.
    let first = &proof.permutation_product_evals[0];
    out.push(lag.l_0 * (Fr::ONE - first.0));

    // (2) L_last(x) · (z_l(x)² − z_l(x)) — last set final.
    let last = &proof.permutation_product_evals[vk.num_perm_chunks - 1];
    out.push(lag.l_last * (last.0.square() - last.0));

    // (3) Chain stitching for chunks i ≥ 1.
    for i in 1..vk.num_perm_chunks {
        let z_i  = proof.permutation_product_evals[i].0;
        let z_im1_last = proof.permutation_product_evals[i - 1].2;
        out.push(lag.l_0 * (z_i - z_im1_last));
    }

    // (4) Per-chunk grand-product step.
    // The actual algebra runs in a separate `chunk_grand_product` function so
    // each chunk gets its own (small) BPF stack frame. Inlining everything
    // into `expressions` produces a 7+KB frame that overflows the 4096-byte
    // SBF stack budget.
    let active = Fr::ONE - lag.l_last - lag.l_blind;
    let delta = field::delta();

    for i in 0..vk.num_perm_chunks {
        let contribution = chunk_grand_product(
            i, chunk_len, num_perm_cols, &proof.advice_evals,
            &proof.permutation_common_evals, &proof.permutation_product_evals,
            ch.beta, ch.gamma, ch.x, delta,
        );
        out.push(active * contribution);
    }

    Ok(out)
}

/// One chunk's grand-product contribution `left − right`. Lives in its own
/// stack frame to keep `expressions`'s frame under the 4096-byte BPF limit.
#[inline(never)]
fn chunk_grand_product(
    i: usize,
    chunk_len: usize,
    num_perm_cols: usize,
    advice_evals: &[Fr],
    perm_common_evals: &[Fr],
    perm_prod_evals: &[(Fr, Fr, Fr)],
    beta: Fr,
    gamma: Fr,
    x: Fr,
    delta: Fr,
) -> Fr {
    let (z, z_omega, _z_last) = perm_prod_evals[i];
    let col_start = i * chunk_len;
    let col_end   = (col_start + chunk_len).min(num_perm_cols);

    // left = z(ωx) · ∏ (advice_eval + β · σ_eval + γ)
    let mut left = z_omega;
    for j in col_start..col_end {
        left *= advice_evals[j] + beta * perm_common_evals[j] + gamma;
    }

    // right = z(x) · ∏ (advice_eval + δⁱ · β · x + γ)
    // current_delta = δ^(i·chunk_len) · β · x → multiplied by δ each loop
    let mut current_delta = pow_fr(delta, (i * chunk_len) as u64) * beta * x;
    let mut right = z;
    for j in col_start..col_end {
        right *= advice_evals[j] + current_delta + gamma;
        current_delta *= delta;
    }
    left - right
}

#[inline(never)]
fn pow_fr(mut base: Fr, mut exp: u64) -> Fr {
    let mut acc = Fr::ONE;
    while exp != 0 {
        if exp & 1 == 1 { acc *= base; }
        base = base.square();
        exp >>= 1;
    }
    acc
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::curve::G1;

    fn synth_vk(num_advice: usize, num_perm_columns: usize, cs_degree: usize, num_perm_chunks: usize) -> PlonkProtocol {
        PlonkProtocol {
            k: 4,
            omega: Fr::ONE,
            num_instance: 0,
            num_advice,
            num_fixed: 0,
            cs_degree,
            num_advice_queries: num_advice,
            num_fixed_queries: 0,
            blinding_factors: 0,
            num_perm_chunks,
            fixed_commitments: Vec::new(),
            permutation_commitments: alloc::vec![G1::IDENTITY; num_perm_columns],
            transcript_repr: [0u8; 32],
        }
    }

    fn synth_lag() -> LagrangeEvaluations {
        LagrangeEvaluations {
            l_0:     Fr::from(2u64),
            l_last:  Fr::from(3u64),
            l_blind: Fr::from(0u64),
            xn:      Fr::from(16u64),
        }
    }

    fn synth_ch() -> Challenges {
        Challenges {
            theta: Fr::from(1u64),
            beta:  Fr::from(7u64),
            gamma: Fr::from(11u64),
            y:     Fr::from(13u64),
            x:     Fr::from(17u64),
            shplonk_y: Fr::ONE,
            shplonk_v: Fr::ONE,
            shplonk_u: Fr::ONE,
        }
    }

    fn synth_proof_one_chunk(num_advice: usize, num_perm_cols: usize) -> PlonkProof {
        PlonkProof {
            advice_commits: alloc::vec![G1::IDENTITY; num_advice],
            permutation_product_commits: alloc::vec![G1::IDENTITY; 1],
            random_poly_commit: G1::IDENTITY,
            vanishing_h_commits: alloc::vec![G1::IDENTITY; 1],
            advice_evals: (0..num_advice).map(|i| Fr::from((i as u64) * 100 + 1)).collect(),
            fixed_evals: Vec::new(),
            random_poly_eval: Fr::ZERO,
            permutation_common_evals: (0..num_perm_cols)
                .map(|i| Fr::from((i as u64) * 7 + 3)).collect(),
            permutation_product_evals: alloc::vec![(Fr::from(31u64), Fr::from(37u64), Fr::from(41u64))],
            opening_proof_w: G1::IDENTITY,
            opening_proof_w_prime: G1::IDENTITY,
        }
    }

    #[test]
    fn expressions_count_single_chunk_one_perm_col() {
        // Single chunk → 3 expressions: (initial, final, chunk_grand_product).
        // Stitching skipped because only 1 chunk.
        let vk = synth_vk(1, 1, 3, 1);
        let proof = synth_proof_one_chunk(1, 1);
        let ch = synth_ch();
        let lag = synth_lag();
        let exprs = expressions(&vk, &proof, &ch, &lag).unwrap();
        assert_eq!(exprs.len(), 3, "1 init + 1 final + 1 grand-product");
    }

    #[test]
    fn expressions_count_two_chunks_two_perm_cols() {
        // 2 chunks → 4 expressions: initial + final + 1 stitching + 2 grand-product.
        let vk = synth_vk(2, 2, 3, 2);
        let mut proof = synth_proof_one_chunk(2, 2);
        proof.permutation_product_evals = alloc::vec![
            (Fr::from(31u64), Fr::from(37u64), Fr::from(41u64)),
            (Fr::from(43u64), Fr::from(47u64), Fr::from(53u64)),
        ];
        proof.permutation_product_commits = alloc::vec![G1::IDENTITY; 2];
        let exprs = expressions(&vk, &proof, &synth_ch(), &synth_lag()).unwrap();
        assert_eq!(exprs.len(), 5);
    }

    /// First expression is `l_0 · (1 - z_first)` — verify exact value.
    #[test]
    fn expressions_first_is_initial_constraint() {
        let vk = synth_vk(1, 1, 3, 1);
        let proof = synth_proof_one_chunk(1, 1);
        let lag = synth_lag(); // l_0 = 2
        let exprs = expressions(&vk, &proof, &synth_ch(), &lag).unwrap();
        // expected = 2 · (1 - 31)
        let expected = Fr::from(2u64) * (Fr::ONE - Fr::from(31u64));
        assert_eq!(exprs[0], expected);
    }

    /// Second expression is `l_last · (z² − z)` — verify exact value.
    #[test]
    fn expressions_second_is_final_constraint() {
        let vk = synth_vk(1, 1, 3, 1);
        let proof = synth_proof_one_chunk(1, 1);
        let lag = synth_lag(); // l_last = 3
        let exprs = expressions(&vk, &proof, &synth_ch(), &lag).unwrap();
        // z = 31, z² − z = 31·31 − 31 = 961 − 31 = 930
        let expected = Fr::from(3u64) * Fr::from(930u64);
        assert_eq!(exprs[1], expected);
    }

    /// Rejects when num_perm_cols > num_advice (our v1 assumption violated).
    #[test]
    fn expressions_rejects_unsupported_column_kind() {
        let vk = synth_vk(1, 2, 3, 1); // 1 advice, 2 perm cols → invalid v1
        let proof = synth_proof_one_chunk(1, 2);
        let r = expressions(&vk, &proof, &synth_ch(), &synth_lag());
        assert!(matches!(r, Err(Error::Protocol(_))));
    }

    /// Rejects when chunk count in proof disagrees with VK metadata.
    #[test]
    fn expressions_rejects_chunk_mismatch() {
        let vk = synth_vk(1, 1, 3, 2);                    // VK says 2 chunks
        let proof = synth_proof_one_chunk(1, 1);          // proof has 1 chunk
        let r = expressions(&vk, &proof, &synth_ch(), &synth_lag());
        assert!(matches!(r, Err(Error::Protocol(_))));
    }

    #[test]
    fn expressions_empty_when_no_permutation() {
        let mut vk = synth_vk(1, 0, 3, 0);
        vk.permutation_commitments = Vec::new();
        let proof = synth_proof_one_chunk(1, 0);
        // Proof has 1 chunk worth of perm_product_evals; need to clear:
        let proof = PlonkProof {
            permutation_product_evals: Vec::new(),
            permutation_common_evals: Vec::new(),
            permutation_product_commits: Vec::new(),
            ..proof
        };
        let exprs = expressions(&vk, &proof, &synth_ch(), &synth_lag()).unwrap();
        assert!(exprs.is_empty());
    }
}
