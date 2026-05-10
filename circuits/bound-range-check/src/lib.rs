//! Phase 2 demo circuit: 4-bit range proof bound to a claimer pubkey hash.
//!
//! What it proves: "I know an `x` in `[0..16)` (Plookup over a 4-bit table)
//! AND my claim is bound to a specific public hash `H` (the on-chain caller's
//! pubkey hashed through keccak256-mod-Fr)."
//!
//! Why bind to a hash. The verifier rejects any proof whose absorbed
//! public-input transcript doesn't match the proof's challenges. So if Eve
//! copies Alice's proof and submits with her own pubkey, the on-chain
//! reward-pool program substitutes Eve's hash into the public-inputs
//! vector → verifier's transcript diverges → proof rejects. This is the
//! cheapest "non-transferable claim" pattern halo2 supports.
//!
//! Constraint surface:
//!   - 1 advice column `x`         (the witness, kept private)
//!   - 1 advice column `bind`      (set to claimer_hash, copy-constrained
//!                                  to instance[0])
//!   - 1 fixed   table `0..15`     (Plookup target)
//!   - 1 instance column `inst[0]` (the claimer hash, public input)
//!
//! Gates:
//!   - lookup("4-bit range", x ∈ table)
//!   - constrain_instance(bind, inst[0])
//!
//! No explicit gate AST; both checks are in halo2's declarative APIs.
//! Proof size for k=6: ~900 B; CU on-chain similar to range-check
//! (single Plookup + single instance query) — fits the 2-tx split.

pub mod circuit;
pub mod prover;
pub mod shadow;

pub use circuit::{BoundRangeCheckCircuit, BRC_BITS, BRC_TABLE_SIZE};
pub use prover::generate_brc_test_vector;
