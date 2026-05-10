//! Shuffle-argument verifier — emits the 3 Fr values per shuffle that
//! halo2's `shuffle::Evaluated::expressions(...)` yields, in declaration
//! order. Slotted into the y-fold in `verifier::compute_expected_h_eval`
//! AFTER the lookup expressions, matching halo2's
//! `iter::chain(lookups).chain(shuffles)` order.
//!
//! Source: `~/.cargo/git/checkouts/halo2-a4679ef32e7b7344/73408a1/halo2_proofs/src/plonk/shuffle/verifier.rs`.
//!
//! For each shuffle the protocol contributes exactly 3 expressions:
//!
//! ```text
//!   expr_1 = l_0    · (1 − product_eval)
//!   expr_2 = l_last · (product_eval² − product_eval)
//!   expr_3 = active · (left − right)
//!
//!   left   = product_next_eval · (shuffle_compressed + γ)
//!   right  = product_eval      · (input_compressed   + γ)
//!   active = 1 − l_last − l_blind
//! ```
//!
//! `input_compressed` / `shuffle_compressed` are theta-folded the same way
//! as in `lookup.rs` (forward Horner: first expression gets the highest θ
//! power). Note shuffle uses *only* γ — there is no β term.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};

use crate::{
    plonk::{expression, Challenges, PlonkProof, PlonkProtocol},
    plonk::lagrange::LagrangeEvaluations,
    Error,
};

/// Emit three expressions per shuffle in halo2's declaration order.
/// Returns `3 · vk.num_shuffles()` `Fr` values.
pub fn expressions(
    vk:              &PlonkProtocol,
    proof:           &PlonkProof,
    ch:              &Challenges,
    lag:             &LagrangeEvaluations,
    instance_evals:  &[Fr],
    user_challenges: &[Fr],
) -> Result<Vec<Fr>, Error> {
    if vk.num_shuffles() == 0 {
        return Ok(Vec::new());
    }
    if proof.shuffle_evals.len() != vk.num_shuffles() {
        return Err(Error::Protocol(
            "shuffle: proof.shuffle_evals length disagrees with vk.num_shuffles",
        ));
    }

    let active = Fr::ONE - lag.l_last - lag.l_blind;

    let ctx = expression::EvalContext {
        advice_evals:    &proof.advice_evals,
        fixed_evals:     &proof.fixed_evals,
        instance_evals,
        user_challenges,
    };

    let mut out: Vec<Fr> = Vec::with_capacity(3 * vk.num_shuffles());
    for (i, arg) in vk.shuffles.iter().enumerate() {
        single_shuffle_expressions(
            arg,
            proof.shuffle_evals[i],
            ch,
            lag,
            active,
            &ctx,
            &mut out,
        )?;
    }
    Ok(out)
}

#[inline(never)]
fn single_shuffle_expressions(
    arg:    &crate::plonk::ShuffleArgument,
    evals:  (Fr, Fr),                              // (product_eval, product_next_eval)
    ch:     &Challenges,
    lag:    &LagrangeEvaluations,
    active: Fr,
    ctx:    &expression::EvalContext<'_>,
    out:    &mut Vec<Fr>,
) -> Result<(), Error> {
    let input_compressed   = compress(&arg.input_expressions,   ch.theta, ctx)?;
    let shuffle_compressed = compress(&arg.shuffle_expressions, ch.theta, ctx)?;

    let z   = evals.0;
    let z_w = evals.1;

    // expr_1: l_0 · (1 − z)
    out.push(lag.l_0 * (Fr::ONE - z));
    // expr_2: l_last · (z² − z)
    out.push(lag.l_last * (z.square() - z));
    // expr_3: active · (z_ω · (shuffle_compressed + γ) − z · (input_compressed + γ))
    out.push(compute_expr_3(z, z_w, ch.gamma, active, input_compressed, shuffle_compressed));
    Ok(())
}

#[inline(never)]
fn compute_expr_3(
    z:                  Fr,
    z_w:                Fr,
    gamma:              Fr,
    active:             Fr,
    input_compressed:   Fr,
    shuffle_compressed: Fr,
) -> Fr {
    let left  = z_w * (shuffle_compressed + gamma);
    let right = z   * (input_compressed   + gamma);
    active * (left - right)
}

/// Theta-fold a list of expression bytecodes into a single Fr (forward Horner).
/// Same shape as `lookup::compress` — kept separate so each verifier
/// argument owns its own `#[inline(never)]` symbol on BPF.
#[inline(never)]
fn compress(
    bytecodes: &[Vec<u8>],
    theta:     Fr,
    ctx:       &expression::EvalContext<'_>,
) -> Result<Fr, Error> {
    let mut acc = Fr::ZERO;
    for bc in bytecodes {
        let v = expression::evaluate(bc, ctx)?;
        acc = acc * theta + v;
    }
    Ok(acc)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::plonk::ShuffleArgument;

    fn synth_lag() -> LagrangeEvaluations {
        LagrangeEvaluations {
            l_0:     Fr::from(2u64),
            l_last:  Fr::from(3u64),
            l_blind: Fr::from(0u64),
            xn:      Fr::from(5u64),
        }
    }
    fn synth_ch() -> Challenges {
        Challenges {
            theta: Fr::from(5u64),
            beta:  Fr::ZERO,
            gamma: Fr::from(11u64),
            y:     Fr::ONE,
            x:     Fr::ONE,
            shplonk_y: Fr::ONE,
            shplonk_v: Fr::ONE,
            shplonk_u: Fr::ONE,
            user_challenges: Vec::new(),
        }
    }
    fn advice_bc(idx: u32) -> Vec<u8> {
        let mut bc = alloc::vec![expression::OP_ADVICE];
        bc.extend_from_slice(&idx.to_le_bytes());
        bc
    }

    fn synth_proto_one_shuffle(input: Vec<Vec<u8>>, shuf: Vec<Vec<u8>>) -> PlonkProtocol {
        PlonkProtocol {
            shuffles: alloc::vec![ShuffleArgument {
                input_expressions: input,
                shuffle_expressions: shuf,
            }],
            ..Default::default()
        }
    }

    fn synth_proof(eval: (Fr, Fr)) -> PlonkProof {
        PlonkProof {
            advice_commits:                Vec::new(),
            permutation_product_commits:   Vec::new(),
            random_poly_commit:            crate::curve::G1::IDENTITY,
            vanishing_h_commits:           Vec::new(),
            advice_evals:                  alloc::vec![Fr::from(7u64)],
            fixed_evals:                   Vec::new(),
            random_poly_eval:              Fr::ZERO,
            permutation_common_evals:      Vec::new(),
            permutation_product_evals:     Vec::new(),
            lookup_permuted_input_commits: Vec::new(),
            lookup_permuted_table_commits: Vec::new(),
            lookup_product_commits:        Vec::new(),
            lookup_evals:                  Vec::new(),
            shuffle_product_commits:       alloc::vec![crate::curve::G1::IDENTITY],
            shuffle_evals:                 alloc::vec![eval],
            opening_proof_w:               crate::curve::G1::IDENTITY,
            opening_proof_w_prime:         crate::curve::G1::IDENTITY,
        }
    }

    #[test]
    fn emits_three_expressions_per_shuffle() {
        let vk = synth_proto_one_shuffle(alloc::vec![advice_bc(0)], alloc::vec![advice_bc(0)]);
        let proof = synth_proof((Fr::ONE, Fr::ONE));
        let r = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]).unwrap();
        assert_eq!(r.len(), 3);
    }

    /// expr_1 = l_0 · (1 − z) = 0 when z = 1.
    #[test]
    fn expr1_zero_when_z_is_one() {
        let vk = synth_proto_one_shuffle(alloc::vec![advice_bc(0)], alloc::vec![advice_bc(0)]);
        let proof = synth_proof((Fr::ONE, Fr::from(42u64)));
        let r = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]).unwrap();
        assert_eq!(r[0], Fr::ZERO);
    }

    /// When `input_compressed == shuffle_compressed` AND `z_w == z`, expr_3
    /// reduces to `active · z · 0 = 0`. With identical input+shuffle expression
    /// lists evaluating to the same Fr, this must hold.
    #[test]
    fn expr3_zero_when_compressions_and_zs_match() {
        let vk = synth_proto_one_shuffle(alloc::vec![advice_bc(0)], alloc::vec![advice_bc(0)]);
        let proof = synth_proof((Fr::from(13u64), Fr::from(13u64)));
        let r = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]).unwrap();
        assert_eq!(r[2], Fr::ZERO);
    }

    /// `vk.num_shuffles() == 0` returns an empty Vec (the no-shuffle happy path).
    #[test]
    fn empty_shuffles_returns_empty() {
        let vk: PlonkProtocol = PlonkProtocol::default();
        let proof = PlonkProof {
            advice_commits:                Vec::new(),
            permutation_product_commits:   Vec::new(),
            random_poly_commit:            crate::curve::G1::IDENTITY,
            vanishing_h_commits:           Vec::new(),
            advice_evals:                  Vec::new(),
            fixed_evals:                   Vec::new(),
            random_poly_eval:              Fr::ZERO,
            permutation_common_evals:      Vec::new(),
            permutation_product_evals:     Vec::new(),
            lookup_permuted_input_commits: Vec::new(),
            lookup_permuted_table_commits: Vec::new(),
            lookup_product_commits:        Vec::new(),
            lookup_evals:                  Vec::new(),
            shuffle_product_commits:       Vec::new(),
            shuffle_evals:                 Vec::new(),
            opening_proof_w:               crate::curve::G1::IDENTITY,
            opening_proof_w_prime:         crate::curve::G1::IDENTITY,
        };
        let r = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]).unwrap();
        assert!(r.is_empty());
    }
}
