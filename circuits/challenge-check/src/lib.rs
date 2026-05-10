//! v2.0 test circuit: single-phase user-defined challenge.
//!
//! Halo2 supports `cs.challenge_usable_after(phase)` to declare a Fiat–Shamir
//! challenge sampled by the verifier mid-protocol. Single-phase circuits
//! (the v2.0 supported case) declare the challenge after FirstPhase advice
//! commits — our `proof_reader::read_proof` squeezes `vk.num_challenges`
//! Fr values right after the advice batch, before theta. The challenge
//! is then accessible inside gate expressions via the `OP_CHALLENGE` opcode.
//!
//! Constraints (1 advice column `a`, 1 challenge `r`, 1 fixed selector
//! `q_sel`, gate `q_sel · r · a = 0`):
//!
//! ```text
//! q_sel(row) · r · a(row) = 0
//! ```
//!
//! Witness: `a = [0, 0, 0, 0]`, so the gate trivially holds for any `r`.
//! At a random verifier point `x`, `a_eval ≠ 0` due to blinding, but the
//! gate identity is still satisfied across the active rows because the
//! prover committed to the correct polynomial. Soundness: any tampering
//! with `a_eval` produces wrong y-fold result → pairing fails.
//!
//! What this exercises:
//!  - VK encoder writes a Phase-0 challenge in `cs.num_challenges` u32 field
//!  - VK encoder writes the gate expression with `OP_CHALLENGE` bytecode
//!  - `read_proof` squeezes 1 user challenge after advice commits
//!  - `evaluate_gates` runs the OP_CHALLENGE branch (reads `user_challenges[0]`)
//!  - Multi-phase rejected at compile-vk time

pub mod circuit;
pub mod prover;

pub use circuit::ChallengeCheckCircuit;
pub use prover::generate_ch_test_vector;
