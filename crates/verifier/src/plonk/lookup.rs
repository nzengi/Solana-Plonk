//! Plookup-style lookup argument verifier — emits the 5 Fr values per
//! lookup that halo2's `lookup::Evaluated::expressions(...)` yields, in
//! declaration order. The y-Horner fold in `verifier::compute_expected_h_eval`
//! splices the result in *after* permutation expressions, matching halo2's
//! `iter::chain(...)` order in `verify_proof`.
//!
//! Source-of-truth reference: `memory/reference_halo2_lookup.md` (extracted
//! from halo2_proofs v0.3.0 `plonk/lookup/verifier.rs`).
//!
//! For each lookup the protocol contributes 5 expressions:
//!
//! ```text
//!   expr_1 = l_0     · (1 − product_eval)
//!   expr_2 = l_last  · (product_eval² − product_eval)
//!   expr_3 = active  · (left − right)             // see below
//!   expr_4 = l_0     · (permuted_input_eval − permuted_table_eval)
//!   expr_5 = active  · (permuted_input_eval − permuted_table_eval)
//!                    · (permuted_input_eval − permuted_input_inv_eval)
//!
//!   left   = product_next_eval · (permuted_input_eval + β) · (permuted_table_eval + γ)
//!   right  = product_eval      · (input_compressed   + β) · (table_compressed   + γ)
//!   active = 1 − l_last − l_blind
//! ```
//!
//! `input_compressed` / `table_compressed` come from theta-folding the
//! per-lookup expression evaluations. Halo2's fold direction is forward —
//! `acc.fold(0, |acc, e| acc·θ + eval(e))` — so the first expression in
//! the input/table list ends up with the highest θ power.

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field};

use crate::{
    plonk::{expression, Challenges, PlonkProof, PlonkProtocol},
    plonk::lagrange::LagrangeEvaluations,
    Error,
};

/// Emit the five expressions per lookup, in halo2's declaration order.
/// Returns `5 · vk.num_lookups()` `Fr` values.
///
/// The per-lookup body lives in `single_lookup_expressions` with
/// `#[inline(never)]` to keep BPF stack frames under the 4096-byte SBF
/// limit (the inlined version blew up to ~6 KB).
pub fn expressions(
    vk:             &PlonkProtocol,
    proof:          &PlonkProof,
    ch:             &Challenges,
    lag:            &LagrangeEvaluations,
    instance_evals: &[Fr],
    user_challenges: &[Fr],
) -> Result<Vec<Fr>, Error> {
    if vk.num_lookups() == 0 {
        return Ok(Vec::new());
    }
    if proof.lookup_evals.len() != vk.num_lookups() {
        return Err(Error::Protocol(
            "lookup: proof.lookup_evals length disagrees with vk.num_lookups",
        ));
    }

    let active = Fr::ONE - lag.l_last - lag.l_blind;

    let ctx = expression::EvalContext {
        advice_evals:    &proof.advice_evals,
        fixed_evals:     &proof.fixed_evals,
        instance_evals,
        user_challenges,
    };

    let mut out: Vec<Fr> = Vec::with_capacity(5 * vk.num_lookups());
    for (i, arg) in vk.lookups.iter().enumerate() {
        single_lookup_expressions(
            arg,
            &proof.lookup_evals[i],
            ch,
            lag,
            active,
            &ctx,
            &mut out,
        )?;
    }
    Ok(out)
}

/// Per-lookup body — pulled out so each invocation has its own BPF stack
/// frame (intermediate Fr values total ~1800 B that would otherwise inline
/// into `expressions`). Further split into `compute_expr_3` to keep each
/// frame under the 4 KB SBF limit.
#[inline(never)]
fn single_lookup_expressions(
    arg:    &crate::plonk::LookupArgument,
    evals:  &crate::plonk::LookupEvals,
    ch:     &Challenges,
    lag:    &LagrangeEvaluations,
    active: Fr,
    ctx:    &expression::EvalContext<'_>,
    out:    &mut Vec<Fr>,
) -> Result<(), Error> {
    let input_compressed = compress(&arg.input_expressions, ch.theta, ctx)?;
    let table_compressed = compress(&arg.table_expressions, ch.theta, ctx)?;

    let z   = evals.product_eval;
    let a_p = evals.permuted_input_eval;
    let s_p = evals.permuted_table_eval;
    let a_m = evals.permuted_input_inv_eval;

    // expr_1: l_0 · (1 − z)
    out.push(lag.l_0 * (Fr::ONE - z));
    // expr_2: l_last · (z² − z)
    out.push(lag.l_last * (z.square() - z));
    // expr_3: active · (left − right) — heaviest Fr arithmetic, isolated frame.
    out.push(compute_expr_3(evals, ch, active, input_compressed, table_compressed));
    // expr_4: l_0 · (a' − s')
    out.push(lag.l_0 * (a_p - s_p));
    // expr_5: active · (a' − s') · (a' − a'_prev)
    out.push(active * (a_p - s_p) * (a_p - a_m));
    Ok(())
}

/// Compute the 3rd lookup expression in its own BPF frame.
/// `active · (z_ω · (a' + β) · (s' + γ) − z · (input_c + β) · (table_c + γ))`
#[inline(never)]
fn compute_expr_3(
    evals:            &crate::plonk::LookupEvals,
    ch:               &Challenges,
    active:           Fr,
    input_compressed: Fr,
    table_compressed: Fr,
) -> Fr {
    let left  = evals.product_next_eval
        * (evals.permuted_input_eval + ch.beta)
        * (evals.permuted_table_eval + ch.gamma);
    let right = evals.product_eval
        * (input_compressed + ch.beta)
        * (table_compressed + ch.gamma);
    active * (left - right)
}

/// Theta-fold a list of expression bytecodes into a single Fr. Direction:
/// forward Horner (`acc·θ + eval(e)`), so the first expression in the list
/// ends up multiplied by the highest power of θ. Empty list ⇒ Fr::ZERO,
/// which is also halo2's default for an "empty fold" branch.
///
/// `#[inline(never)]` so the bytecode evaluator's stack temporaries don't
/// inline into `single_lookup_expressions` (BPF SBF stack budget is 4 KB).
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
    use crate::plonk::{LookupArgument, LookupEvals};

    fn synth_proto_one_lookup(input_bcs: Vec<Vec<u8>>, table_bcs: Vec<Vec<u8>>) -> PlonkProtocol {
        PlonkProtocol {
            cs_degree: 4,
            num_advice_queries: 1,
            num_fixed_queries: 1,
            lookups: alloc::vec![LookupArgument {
                input_expressions: input_bcs,
                table_expressions: table_bcs,
            }],
            ..Default::default()
        }
    }

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
            theta: Fr::from(1u64),
            beta:  Fr::from(7u64),
            gamma: Fr::from(11u64),
            y:     Fr::ONE,
            x:     Fr::ONE,
            shplonk_y: Fr::ONE,
            shplonk_v: Fr::ONE,
            shplonk_u: Fr::ONE,
            user_challenges: Vec::new(),
        }
    }

    fn synth_proof(le: LookupEvals) -> PlonkProof {
        PlonkProof {
            advice_commits:                Vec::new(),
            permutation_product_commits:   Vec::new(),
            random_poly_commit:            crate::curve::G1::IDENTITY,
            vanishing_h_commits:           Vec::new(),
            advice_evals:                  alloc::vec![Fr::from(13u64)],
            fixed_evals:                   alloc::vec![Fr::from(17u64)],
            random_poly_eval:              Fr::ZERO,
            permutation_common_evals:      Vec::new(),
            permutation_product_evals:     Vec::new(),
            lookup_permuted_input_commits: alloc::vec![crate::curve::G1::IDENTITY],
            lookup_permuted_table_commits: alloc::vec![crate::curve::G1::IDENTITY],
            lookup_product_commits:        alloc::vec![crate::curve::G1::IDENTITY],
            lookup_evals:                  alloc::vec![le],
            shuffle_product_commits:       Vec::new(),
            shuffle_evals:                 Vec::new(),
            opening_proof_w:               crate::curve::G1::IDENTITY,
            opening_proof_w_prime:         crate::curve::G1::IDENTITY,
        }
    }

    /// `Advice(0) @ rotation 0` evaluates to `proof.advice_evals[0]`.
    /// `Fixed(0)  @ rotation 0` evaluates to `proof.fixed_evals[0]`.
    /// Both bytecodes are 5 bytes: opcode + u32 query index (LE).
    fn advice_bc(idx: u32) -> Vec<u8> {
        let mut bc = alloc::vec![expression::OP_ADVICE];
        bc.extend_from_slice(&idx.to_le_bytes());
        bc
    }
    fn fixed_bc(idx: u32) -> Vec<u8> {
        let mut bc = alloc::vec![expression::OP_FIXED];
        bc.extend_from_slice(&idx.to_le_bytes());
        bc
    }

    #[test]
    fn emits_five_expressions_per_lookup() {
        let vk    = synth_proto_one_lookup(alloc::vec![advice_bc(0)], alloc::vec![fixed_bc(0)]);
        let proof = synth_proof(LookupEvals {
            product_eval:            Fr::ONE,
            product_next_eval:       Fr::ONE,
            permuted_input_eval:     Fr::from(13u64),
            permuted_input_inv_eval: Fr::from(13u64),
            permuted_table_eval:     Fr::from(17u64),
        });
        let exprs = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]).unwrap();
        assert_eq!(exprs.len(), 5);
    }

    /// expr_1 = l_0 · (1 − z). With l_0 = 2 and z = 1, expr_1 = 0.
    #[test]
    fn expr1_zero_when_z_is_one() {
        let vk    = synth_proto_one_lookup(alloc::vec![advice_bc(0)], alloc::vec![fixed_bc(0)]);
        let proof = synth_proof(LookupEvals {
            product_eval:            Fr::ONE,
            product_next_eval:       Fr::ONE,
            permuted_input_eval:     Fr::from(13u64),
            permuted_input_inv_eval: Fr::from(13u64),
            permuted_table_eval:     Fr::from(17u64),
        });
        let exprs = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]).unwrap();
        assert_eq!(exprs[0], Fr::ZERO);
    }

    /// expr_4 = l_0 · (a' − s'). With a' = s' the expression must be zero
    /// regardless of l_0 — it's the "first-row equality" lookup boundary
    /// constraint.
    #[test]
    fn expr4_zero_when_permuted_input_equals_table_at_row_0() {
        let vk    = synth_proto_one_lookup(alloc::vec![advice_bc(0)], alloc::vec![fixed_bc(0)]);
        let proof = synth_proof(LookupEvals {
            product_eval:            Fr::ONE,
            product_next_eval:       Fr::ONE,
            permuted_input_eval:     Fr::from(42u64),
            permuted_input_inv_eval: Fr::from(42u64),
            permuted_table_eval:     Fr::from(42u64),
        });
        let exprs = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]).unwrap();
        assert_eq!(exprs[3], Fr::ZERO);
    }

    /// Empty `vk.lookups` returns an empty Vec — the v1.5 happy path.
    #[test]
    fn empty_lookups_returns_empty() {
        let vk: PlonkProtocol = PlonkProtocol::default();
        let proof = synth_proof(LookupEvals {
            product_eval: Fr::ZERO, product_next_eval: Fr::ZERO,
            permuted_input_eval: Fr::ZERO,
            permuted_input_inv_eval: Fr::ZERO,
            permuted_table_eval: Fr::ZERO,
        });
        // Drop the synthetic eval to match an actual no-lookup proof:
        let proof = PlonkProof { lookup_evals: Vec::new(), ..proof };
        let exprs = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]).unwrap();
        assert!(exprs.is_empty());
    }

    /// Theta-fold direction: with one expression and θ = anything, compress
    /// returns just that expression's eval (acc starts at 0, fold yields v).
    #[test]
    fn compress_single_expression_equals_eval() {
        let ctx = expression::EvalContext {
            advice_evals:    &alloc::vec![Fr::from(99u64)],
            fixed_evals:     &Vec::new(),
            instance_evals:  &Vec::new(),
            user_challenges: &Vec::new(),
        };
        let bc = advice_bc(0);
        let r  = compress(&alloc::vec![bc], Fr::from(7u64), &ctx).unwrap();
        assert_eq!(r, Fr::from(99u64));
    }

    /// Two expressions: first multiplied by θ, second added — forward Horner.
    #[test]
    fn compress_two_expressions_horner() {
        let ctx = expression::EvalContext {
            advice_evals:    &alloc::vec![Fr::from(2u64), Fr::from(3u64)],
            fixed_evals:     &Vec::new(),
            instance_evals:  &Vec::new(),
            user_challenges: &Vec::new(),
        };
        // Expressions = [advice[0], advice[1]] = [2, 3]; θ = 5.
        // Expected: 2·5 + 3 = 13.
        let r = compress(&alloc::vec![advice_bc(0), advice_bc(1)],
                         Fr::from(5u64), &ctx).unwrap();
        assert_eq!(r, Fr::from(13u64));
    }

    /// Multi-lookup regression: 2 lookups in one circuit must produce
    /// 5 × 2 = 10 expressions in declaration order. Catches off-by-one
    /// in the lookup-iteration loop and confirms `proof.lookup_evals[i]`
    /// is indexed correctly per-lookup.
    #[test]
    fn two_lookups_emit_ten_expressions_in_order() {
        // Two lookups:
        //   lookup_0: input = advice[0], table = fixed[0]
        //   lookup_1: input = advice[1], table = fixed[1]
        let vk = PlonkProtocol {
            cs_degree: 4,
            num_advice_queries: 2,
            num_fixed_queries: 2,
            lookups: alloc::vec![
                LookupArgument {
                    input_expressions: alloc::vec![advice_bc(0)],
                    table_expressions: alloc::vec![fixed_bc(0)],
                },
                LookupArgument {
                    input_expressions: alloc::vec![advice_bc(1)],
                    table_expressions: alloc::vec![fixed_bc(1)],
                },
            ],
            ..Default::default()
        };

        // Distinct evals per lookup so we can detect cross-contamination.
        // For lookup_0 we set a' = s' = 13 so expr_4 = l_0·(a'-s') = 0;
        // expr_4's value distinguishes whether the loop indexed lookup_0
        // correctly (NOT picking up lookup_1's a'/s' = 23/29).
        let evals_0 = LookupEvals {
            product_eval:            Fr::ONE,
            product_next_eval:       Fr::ONE,
            permuted_input_eval:     Fr::from(13u64),
            permuted_input_inv_eval: Fr::from(13u64),
            permuted_table_eval:     Fr::from(13u64),
        };
        let evals_1 = LookupEvals {
            product_eval:            Fr::from(2u64),
            product_next_eval:       Fr::from(2u64),
            permuted_input_eval:     Fr::from(23u64),
            permuted_input_inv_eval: Fr::from(23u64),
            permuted_table_eval:     Fr::from(29u64),
        };

        let proof = PlonkProof {
            advice_commits:                Vec::new(),
            permutation_product_commits:   Vec::new(),
            random_poly_commit:            crate::curve::G1::IDENTITY,
            vanishing_h_commits:           Vec::new(),
            advice_evals:                  alloc::vec![Fr::from(13u64), Fr::from(23u64)],
            fixed_evals:                   alloc::vec![Fr::from(17u64), Fr::from(29u64)],
            random_poly_eval:              Fr::ZERO,
            permutation_common_evals:      Vec::new(),
            permutation_product_evals:     Vec::new(),
            lookup_permuted_input_commits: alloc::vec![
                crate::curve::G1::IDENTITY, crate::curve::G1::IDENTITY,
            ],
            lookup_permuted_table_commits: alloc::vec![
                crate::curve::G1::IDENTITY, crate::curve::G1::IDENTITY,
            ],
            lookup_product_commits:        alloc::vec![
                crate::curve::G1::IDENTITY, crate::curve::G1::IDENTITY,
            ],
            lookup_evals:                  alloc::vec![evals_0, evals_1],
            shuffle_product_commits:       Vec::new(),
            shuffle_evals:                 Vec::new(),
            opening_proof_w:               crate::curve::G1::IDENTITY,
            opening_proof_w_prime:         crate::curve::G1::IDENTITY,
        };

        let exprs = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]).unwrap();
        assert_eq!(exprs.len(), 10, "5 expressions × 2 lookups");

        // exprs[0..5] correspond to lookup_0; exprs[5..10] to lookup_1.
        // Lookup_0: a' = s' = 13, so expr_4 = l_0 · (a'-s') = 0.
        assert_eq!(exprs[3], Fr::ZERO, "lookup_0 expr_4 should be 0 (a'=s')");
        // Lookup_1: a' = 23, s' = 29 → expr_4 = l_0 · (23-29) = 2 · (-6) = -12.
        assert_eq!(
            exprs[3 + 5],
            Fr::from(2u64) * (Fr::from(23u64) - Fr::from(29u64)),
            "lookup_1 expr_4 should reflect a'-s' for lookup_1's evals, NOT lookup_0's",
        );
    }

    /// Mismatched proof.lookup_evals length vs vk.num_lookups must error
    /// (don't silently accept a malformed proof with too few/many evals).
    #[test]
    fn lookup_evals_length_mismatch_rejects() {
        let vk = PlonkProtocol {
            cs_degree: 4,
            lookups: alloc::vec![
                LookupArgument {
                    input_expressions: alloc::vec![advice_bc(0)],
                    table_expressions: alloc::vec![fixed_bc(0)],
                },
                LookupArgument {
                    input_expressions: alloc::vec![advice_bc(0)],
                    table_expressions: alloc::vec![fixed_bc(0)],
                },
            ],
            ..Default::default()
        };
        // proof has only 1 lookup_evals, but vk says 2.
        let proof = synth_proof(LookupEvals {
            product_eval: Fr::ONE, product_next_eval: Fr::ONE,
            permuted_input_eval: Fr::ZERO, permuted_input_inv_eval: Fr::ZERO,
            permuted_table_eval: Fr::ZERO,
        });
        let r = expressions(&vk, &proof, &synth_ch(), &synth_lag(), &[], &[]);
        assert!(matches!(r, Err(crate::Error::Protocol(_))));
    }
}
