//! PSE-Halo2 PLONKish protocol — flat on-chain VK + proof structs and the
//! main verifier entry point.
//!
//! v1 scope: specialised to **StandardPlonk-shaped circuits** (no lookups,
//! no shuffles, no challenges-in-phases, single permutation chunk, queries
//! at rotation 0 only). Generic gate-expression AST evaluation is v1.5.

pub mod expression;
pub mod lagrange;
pub mod lookup;
pub mod permutation;
pub mod proof_reader;
pub mod shuffle;
pub mod verifier;

use alloc::vec::Vec;
use ark_bn254::Fr;

use crate::curve::G1;

/// On-chain flattened representation of a Halo2 verifying key.
///
/// v1.5 extensions over v1: query-column metadata + gate AST bytecode +
/// permutation column type tags. v1's hard-coded StandardPlonk gate is
/// replaced by a generic bytecode evaluator (see `plonk::expression`).
#[derive(Clone, Debug)]
pub struct PlonkProtocol {
    pub k: u32,                       // log2 of circuit rows
    pub omega: Fr,                    // domain generator (2^k-th root of unity)
    pub num_instance: usize,
    pub num_advice: usize,
    pub num_fixed: usize,

    pub cs_degree: usize,             // ConstraintSystem::degree()
    pub num_advice_queries: usize,    // total advice column queries (sum over rotations)
    pub num_fixed_queries: usize,
    pub num_instance_queries: usize,  // v1.5: instance column queries
    pub num_challenges: usize,        // v1.5: user-defined phase challenges
    pub blinding_factors: usize,      // # of last rows reserved for blinders
    pub num_perm_chunks: usize,       // ceil(num_perm_columns / chunk_len)

    pub fixed_commitments: Vec<G1>,
    pub permutation_commitments: Vec<G1>,

    /// v1.5: query-column metadata. Each entry is `(column_index, rotation)`.
    /// Index in this Vec matches the `query.index` halo2 stores in its
    /// `Expression::{Advice, Fixed, Instance}` variants → so the bytecode
    /// evaluator can look up `proof.{advice,fixed,instance}_evals[idx]`
    /// directly.
    pub advice_queries:   Vec<(u32, i32)>,
    pub fixed_queries:    Vec<(u32, i32)>,
    pub instance_queries: Vec<(u32, i32)>,

    /// v1.5: gate constraint bytecode. Outer Vec = one entry per
    /// `vk.cs.gates[i]`; inner Vec = one entry per `gate.polynomials()[j]`;
    /// innermost is the RPN bytecode evaluated by `plonk::expression::evaluate`.
    pub gates: Vec<Vec<Vec<u8>>>,

    /// v1.5: permuted column types. Each entry is `(col_type, query_index)`
    /// where `col_type ∈ {0=advice, 1=fixed, 2=instance}` and `query_index`
    /// indexes into the matching `*_queries` list above.
    pub permuted_columns: Vec<(u8, u32)>,

    /// v2.0: lookup arguments. Each entry has its input + table expression
    /// bytecode lists; the verifier theta-folds them into a single Fr at
    /// runtime. Empty for circuits without lookups.
    pub lookups: Vec<LookupArgument>,

    /// v2.0: shuffle arguments. Simpler than lookups (single product commit
    /// per shuffle, no permuted-input/table machinery).
    pub shuffles: Vec<ShuffleArgument>,

    /// Pre-computed Blake2b("Halo2-Verify-Key" || …) → `transcript_repr`.
    /// Computed off-chain by the VK compiler so the on-chain verifier never
    /// has to run Blake2b.
    pub transcript_repr: [u8; 32],
}

/// One lookup argument's spec — pulled from `vk.cs.lookups()` and encoded
/// into VK bytes. Each expression is RPN bytecode for the expression
/// evaluator (same surface as gate ASTs).
#[derive(Clone, Debug, Default)]
pub struct LookupArgument {
    /// Input expressions (one per matched column). Theta-folded at runtime
    /// into `input_compressed`.
    pub input_expressions: Vec<Vec<u8>>,
    /// Table expressions (must have the same count as `input_expressions`).
    pub table_expressions: Vec<Vec<u8>>,
}

/// One shuffle argument's spec. Halo2's shuffle is a permutation argument
/// over a sub-set; the verifier reads one product commit per shuffle and
/// emits a small expression set (handled in v2.0 task #45).
#[derive(Clone, Debug, Default)]
pub struct ShuffleArgument {
    /// Input expressions for the shuffled side.
    pub input_expressions: Vec<Vec<u8>>,
    /// Reference expressions (the side the input must be a shuffle of).
    pub shuffle_expressions: Vec<Vec<u8>>,
}

impl PlonkProtocol {
    pub fn num_perm_columns(&self) -> usize {
        self.permutation_commitments.len()
    }
    pub fn num_lookups(&self) -> usize { self.lookups.len() }
    pub fn num_shuffles(&self) -> usize { self.shuffles.len() }
}

#[cfg(any(test, feature = "std"))]
impl Default for PlonkProtocol {
    /// Synthetic empty VK — only useful for unit tests that need a placeholder.
    fn default() -> Self {
        use ark_ff::AdditiveGroup;
        Self {
            k: 0,
            omega: Fr::ZERO,
            num_instance: 0,
            num_advice: 0,
            num_fixed: 0,
            cs_degree: 0,
            num_advice_queries: 0,
            num_fixed_queries: 0,
            num_instance_queries: 0,
            num_challenges: 0,
            blinding_factors: 0,
            num_perm_chunks: 0,
            fixed_commitments: Vec::new(),
            permutation_commitments: Vec::new(),
            advice_queries: Vec::new(),
            fixed_queries: Vec::new(),
            instance_queries: Vec::new(),
            gates: Vec::new(),
            permuted_columns: Vec::new(),
            lookups: Vec::new(),
            shuffles: Vec::new(),
            transcript_repr: [0u8; 32],
        }
    }
}

/// Parsed proof bytes — every G1 commitment and Fr evaluation the prover sent.
/// Field order mirrors PSE-Halo2 verifier's `verify_proof` read sequence.
#[derive(Clone, Debug)]
pub struct PlonkProof {
    /// (1) Advice column commitments — `num_advice` G1 points.
    pub advice_commits: Vec<G1>,
    /// (2) Permutation grand-product commitments — `num_perm_chunks` G1 points.
    pub permutation_product_commits: Vec<G1>,
    /// (3) Vanishing argument's "before y" random poly commitment — 1 G1.
    pub random_poly_commit: G1,
    /// (4) Vanishing argument's `h(X)` pieces — `cs_degree - 1` G1 points.
    pub vanishing_h_commits: Vec<G1>,
    /// (5) Advice column evaluations at challenge x (and rotations) — `num_advice_queries`.
    pub advice_evals: Vec<Fr>,
    /// (6) Fixed column evaluations — `num_fixed_queries`.
    pub fixed_evals: Vec<Fr>,
    /// (7) Random poly evaluation at x — 1 Fr.
    pub random_poly_eval: Fr,
    /// (8) Permutation common evaluations (one per perm column at x) —
    /// `num_perm_columns` Fr.
    pub permutation_common_evals: Vec<Fr>,
    /// (9) Permutation product evaluations (z, z_omega, z_last) per chunk —
    /// `num_perm_chunks` triples.
    pub permutation_product_evals: Vec<(Fr, Fr, Fr)>,

    // ── v2.0 lookup additions ────────────────────────────────────────────
    /// Per-lookup permuted-input commitments. Length = `num_lookups`.
    pub lookup_permuted_input_commits: Vec<G1>,
    /// Per-lookup permuted-table commitments. Length = `num_lookups`.
    pub lookup_permuted_table_commits: Vec<G1>,
    /// Per-lookup grand-product commitments. Length = `num_lookups`.
    pub lookup_product_commits: Vec<G1>,
    /// Per-lookup five evaluations:
    /// `(product_eval, product_next_eval, permuted_input_eval,
    ///   permuted_input_inv_eval, permuted_table_eval)`
    pub lookup_evals: Vec<LookupEvals>,

    // ── v2.0 shuffle additions ──────────────────────────────────────────
    /// Per-shuffle product commitments. Length = `num_shuffles`.
    pub shuffle_product_commits: Vec<G1>,
    /// Per-shuffle two evaluations: `(product_eval, product_next_eval)`.
    pub shuffle_evals: Vec<(Fr, Fr)>,

    /// (10) SHPLONK opening proof — two G1 points.
    pub opening_proof_w: G1,
    pub opening_proof_w_prime: G1,
}

/// Five `Fr` values halo2 emits per lookup, in this exact transcript order.
#[derive(Clone, Copy, Debug)]
pub struct LookupEvals {
    pub product_eval: Fr,
    pub product_next_eval: Fr,
    pub permuted_input_eval: Fr,
    pub permuted_input_inv_eval: Fr,
    pub permuted_table_eval: Fr,
}

/// Fiat–Shamir challenges derived during proof reading.
///
/// Halo2's main protocol challenges (theta/beta/gamma/y/x) plus the SHPLONK
/// opening challenges (shplonk_y / shplonk_v / shplonk_u). v2.0 also stores
/// the user-defined per-phase challenges that gates may reference via the
/// RPN bytecode `OP_CHALLENGE` opcode.
#[derive(Clone, Debug)]
pub struct Challenges {
    pub theta: Fr,   // squeezed always (compress lookup columns); unused if no lookups
    pub beta:  Fr,
    pub gamma: Fr,
    pub y:     Fr,
    pub x:     Fr,
    /// SHPLONK opening's "y" — combines polynomials within a rotation set.
    pub shplonk_y: Fr,
    /// SHPLONK opening's "v" — combines rotation sets via random linear combo.
    pub shplonk_v: Fr,
    /// SHPLONK opening's "u" — the evaluation point of the linearization poly.
    pub shplonk_u: Fr,
    /// User-defined phase challenges, one per `vk.cs.num_challenges`. Empty
    /// for circuits with no challenge_phase declarations.
    pub user_challenges: Vec<Fr>,
}
