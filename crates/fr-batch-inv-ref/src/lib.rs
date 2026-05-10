//! BN254 scalar-field batch-inverse reference implementation
//! (`SIMD-XXXX-alt-bn128-fr-batch-inverse`).
//!
//! Computes `(s₁⁻¹, …, sₙ⁻¹)` in the BN254 scalar field `Fr` using
//! Montgomery's batch-inverse trick. Cost: **1 modular inverse + 3·(n−1)
//! multiplications**, regardless of n. Same surface as halo2curves's
//! `Field::batch_invert` and arkworks's `batch_inversion` — re-implemented
//! here as a no_std reference for the agave native syscall to mirror.
//!
//! ## Algorithm
//!
//! Given `s = (s₀, s₁, …, s_{n-1})`:
//!
//! 1. **Forward pass**: compute prefix products `p[i] = s₀ · s₁ · … · sᵢ`.
//! 2. **One inverse**: `inv_total = (s₀ · … · s_{n-1})⁻¹`.
//! 3. **Backward pass**: at step `i` (from n-1 down to 1):
//!    * `sᵢ⁻¹ = inv_total · p[i-1]`
//!    * `inv_total *= sᵢ`   (so `inv_total` becomes `(s₀ · … · sᵢ₋₁)⁻¹`)
//! 4. At step 0: `s₀⁻¹ = inv_total`.
//!
//! Output is the inverses `(s₀⁻¹, …, s_{n-1}⁻¹)` in input order.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::{Field, Zero};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// One of the input scalars is zero — no inverse exists.
    ZeroInverse,
}

/// Compute the inverses of `scalars` in batch via Montgomery's trick.
/// Returns inverses in the same order as the input.
///
/// Edge cases:
/// - `scalars.is_empty()` returns an empty Vec.
/// - `scalars.len() == 1` falls back to a direct `Fr::inverse()` call.
/// - Any scalar = 0 ⇒ `Err(Error::ZeroInverse)` (no inverse defined).
pub fn batch_inverse(scalars: &[Fr]) -> Result<Vec<Fr>, Error> {
    if scalars.is_empty() {
        return Ok(Vec::new());
    }
    if scalars.iter().any(|s| s.is_zero()) {
        return Err(Error::ZeroInverse);
    }

    let n = scalars.len();
    if n == 1 {
        return Ok(alloc::vec![scalars[0].inverse().expect("non-zero")]);
    }

    // Forward pass: prefix products. products[i] = s_0 · s_1 · ... · s_i.
    let mut products: Vec<Fr> = Vec::with_capacity(n);
    products.push(scalars[0]);
    for i in 1..n {
        let prev = products[i - 1];
        products.push(prev * scalars[i]);
    }

    // One inverse: (s_0 · s_1 · ... · s_{n-1})⁻¹.
    let mut inv_total = products[n - 1].inverse().expect("non-zero product");

    // Backward pass.
    let mut inverses: Vec<Fr> = alloc::vec![Fr::zero(); n];
    for i in (1..n).rev() {
        // s_i⁻¹ = inv_total · (s_0 · ... · s_{i-1}) = inv_total · products[i-1]
        inverses[i] = inv_total * products[i - 1];
        // Update inv_total to be (s_0 · ... · s_{i-1})⁻¹
        inv_total *= scalars[i];
    }
    inverses[0] = inv_total;

    Ok(inverses)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use ark_ff::UniformRand;

    fn assert_inv_pair(s: Fr, s_inv: Fr) {
        assert_eq!(s * s_inv, Fr::from(1u64), "s * s⁻¹ != 1");
    }

    #[test]
    fn empty_input_returns_empty() {
        assert!(batch_inverse(&[]).unwrap().is_empty());
    }

    #[test]
    fn single_input_uses_direct_inverse() {
        let s = Fr::from(7u64);
        let r = batch_inverse(&[s]).unwrap();
        assert_eq!(r.len(), 1);
        assert_inv_pair(s, r[0]);
    }

    #[test]
    fn small_batch_matches_naive_inverses() {
        let scalars: Vec<Fr> = (1u64..=8).map(Fr::from).collect();
        let batch = batch_inverse(&scalars).unwrap();
        for (s, s_inv) in scalars.iter().zip(batch.iter()) {
            assert_inv_pair(*s, *s_inv);
        }
    }

    #[test]
    fn large_random_batch_correct() {
        let mut rng = ark_std::test_rng();
        let n = 64;
        let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
        let batch = batch_inverse(&scalars).unwrap();
        for (s, s_inv) in scalars.iter().zip(batch.iter()) {
            assert_inv_pair(*s, *s_inv);
        }
    }

    #[test]
    fn zero_in_batch_rejected() {
        let scalars = alloc::vec![Fr::from(3u64), Fr::from(0u64), Fr::from(5u64)];
        assert_eq!(batch_inverse(&scalars), Err(Error::ZeroInverse));
    }

    /// Batch inverse output order matches input order (positional, not
    /// sorted).
    #[test]
    fn output_preserves_input_order() {
        let scalars: Vec<Fr> = alloc::vec![
            Fr::from(13u64), Fr::from(2u64), Fr::from(99u64), Fr::from(7u64),
        ];
        let batch = batch_inverse(&scalars).unwrap();
        let naive: Vec<Fr> = scalars.iter().map(|s| s.inverse().unwrap()).collect();
        for (b, n) in batch.iter().zip(naive.iter()) {
            assert_eq!(b, n, "batch differs from naive at same index");
        }
    }

    /// Two inverses: simplest non-trivial case for the prefix-products path.
    #[test]
    fn two_inputs_correct() {
        let a = Fr::from(11u64);
        let b = Fr::from(13u64);
        let r = batch_inverse(&[a, b]).unwrap();
        assert_inv_pair(a, r[0]);
        assert_inv_pair(b, r[1]);
    }
}
