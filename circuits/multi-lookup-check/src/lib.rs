//! v2.0 test circuit: TWO Plookup arguments in one circuit.
//!
//! Critical regression test for the v2.0 lookup verifier's iteration
//! loop. The single-lookup `range-check` circuit only exercises i = 0
//! in the loop bodies; an off-by-one in `proof.lookup_evals[i]`,
//! `vk.lookups[i]`, or `lookup_*_commits[i]` would silently pass on
//! single-lookup but fail here on two.
//!
//! Constraints:
//!  * `lo_value ∈ 4-bit table   (0..16)` — lookup #0
//!  * `hi_value ∈ 3-bit table   (0..8)`  — lookup #1
//!
//! Two distinct table columns ⇒ halo2 emits two separate
//! `lookup::Argument` entries; the verifier must read 6 G1 + 10 Fr
//! per proof (vs 3 G1 + 5 Fr for single-lookup).

pub mod circuit;
pub mod prover;
pub mod shadow;

pub use circuit::MultiLookupCircuit;
pub use prover::generate_ml_test_vector;
