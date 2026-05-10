//! v2.0 test circuit: 4-bit range check via Plookup.
//!
//! Constraints (1 advice column `value`, 1 lookup table column populated
//! with `0..16`, 1 lookup constraint asserting `value @ Rotation::cur()`
//! appears in the table):
//!
//! ```text
//! lookup("4-bit range", |meta| {
//!     vec![ ( meta.query_advice(value, Rotation::cur()), table ) ]
//! });
//! ```
//!
//! Why this circuit for v2.0:
//!  - First circuit with `cs.lookups()` non-empty — exercises the entire
//!    lookup verifier path in `halo2-solana-verifier`:
//!      * VK encoder writes lookup-argument bytecode (#40)
//!      * Proof reader pulls the per-lookup 3 G1 + 5 Fr (#38)
//!      * `lookup::expressions` emits 5 Fr per lookup (#41)
//!      * `build_queries` emits 5 SHPLONK queries per lookup (#42)
//!  - No instance column, no extra gates → minimum surface area for
//!    debugging when the verifier disagrees with halo2's prover.
//!  - Small table (16 entries) keeps proof generation fast at k=6.

pub mod circuit;
pub mod prover;
pub mod shadow;

pub use circuit::{RangeCheckCircuit, RC_BITS, RC_TABLE_SIZE, RC_VALUE_COUNT};
pub use prover::generate_rc_test_vector;
