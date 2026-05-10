//! v1.5 test circuit: Fibonacci.
//!
//! Constraints (1 gate, 1 advice column `a`, 1 fixed selector `q_fib`,
//! 1 instance column `target`):
//!
//! ```text
//! q_fib(row) · ( a(row) + a(row+1) - a(row+2) ) = 0
//! ```
//!
//! With initial values `a(0) = 1`, `a(1) = 1` and the constraint enabled
//! at every row up to N-2, this produces the Fibonacci sequence in column
//! `a`. Public input asserts the final value `a(N-1) == target`.
//!
//! Why this circuit for v1.5:
//!  - Exercises `Rotation::next()` and `Rotation(2)` advice queries
//!    (StandardPlonk only used `Rotation::cur()`).
//!  - Exercises an **instance column** (StandardPlonk has none) — drives
//!    the instance-eval Lagrange-basis path in the verifier (#28).
//!  - Different gate AST shape than StandardPlonk → exercises
//!    `evaluate_gates` on a non-trivial second circuit.

pub mod circuit;
pub mod prover;

pub use circuit::FibonacciCircuit;
pub use prover::generate_fib_test_vector;
