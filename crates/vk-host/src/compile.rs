//! halo2 `VerifyingKey<G1Affine>`  →  on-chain `PlonkProtocol` byte stream.

use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;

use crate::encode::{fr_to_bytes_be, g1_affine_to_bytes_be, VK_MAGIC, VK_VERSION};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("halo2 VK could not be compiled into PlonkProtocol: {0}")]
    Compile(&'static str),
    #[error("encoding failure: {0}")]
    Encode(&'static str),
}

/// Compile a halo2 (BN254/KZG) verifying key plus its KZG params into the
/// flat on-chain byte format consumed by `halo2_solana_verifier::vk::parse_vk`.
///
/// `params` is needed because `VerifyingKey` does not expose its
/// `EvaluationDomain` publicly — we read `k` and derive `omega` ourselves.
pub fn compile_vk(
    params: &ParamsKZG<halo2curves::bn256::Bn256>,
    vk: &VerifyingKey<G1Affine>,
) -> Result<Vec<u8>, Error> {
    let k = params.k();
    let omega = compute_omega(k);

    let cs = vk.cs();
    let num_instance       = cs.num_instance_columns();
    let num_advice         = cs.num_advice_columns();
    let num_fixed          = cs.num_fixed_columns();
    let cs_degree          = cs.degree();
    let num_advice_queries = cs.advice_queries().len();
    let num_fixed_queries  = cs.fixed_queries().len();
    let blinding_factors   = cs.blinding_factors();

    // Halo2's permutation argument splits perm columns into chunks sized by
    // `chunk_len = cs_degree - 2` (the constraint-degree budget for the
    // grand-product polynomial). At least 1 chunk if any perm columns exist.
    let perm_columns = vk.permutation().commitments().len();
    let chunk_len = cs_degree.saturating_sub(2).max(1);
    let num_perm_chunks = if perm_columns == 0 { 0 } else { (perm_columns + chunk_len - 1) / chunk_len };

    let transcript_repr = vk.transcript_repr();
    let transcript_repr_be = fr_to_bytes_be(&transcript_repr);

    let fixed = vk.fixed_commitments();
    let perm  = vk.permutation().commitments();

    let mut out = Vec::with_capacity(
        8 + 10 * 4 + 64 + (4 + 64 * fixed.len()) + (4 + 64 * perm.len()),
    );
    out.extend_from_slice(VK_MAGIC);
    out.extend_from_slice(&VK_VERSION.to_le_bytes());
    out.extend_from_slice(&k.to_le_bytes());
    out.extend_from_slice(&(num_instance       as u32).to_le_bytes());
    out.extend_from_slice(&(num_advice         as u32).to_le_bytes());
    out.extend_from_slice(&(num_fixed          as u32).to_le_bytes());
    out.extend_from_slice(&(cs_degree          as u32).to_le_bytes());
    out.extend_from_slice(&(num_advice_queries as u32).to_le_bytes());
    out.extend_from_slice(&(num_fixed_queries  as u32).to_le_bytes());
    out.extend_from_slice(&(blinding_factors   as u32).to_le_bytes());
    out.extend_from_slice(&(num_perm_chunks    as u32).to_le_bytes());
    out.extend_from_slice(&fr_to_bytes_be(&omega));
    out.extend_from_slice(&transcript_repr_be);

    out.extend_from_slice(&(fixed.len() as u32).to_le_bytes());
    for p in fixed { out.extend_from_slice(&g1_affine_to_bytes_be(p)); }

    out.extend_from_slice(&(perm.len() as u32).to_le_bytes());
    for p in perm { out.extend_from_slice(&g1_affine_to_bytes_be(p)); }

    Ok(out)
}

/// Compute ω, the primitive 2^k root of unity in BN254 Fr, by squaring
/// `Fr::ROOT_OF_UNITY` (which is a 2^S-th root) the right number of times.
fn compute_omega(k: u32) -> Fr {
    use halo2curves::ff::PrimeField;
    let s = Fr::S; // largest power of 2 dividing p-1
    assert!(k <= s, "k = {k} exceeds Fr::S = {s}");
    let mut omega = Fr::ROOT_OF_UNITY;
    for _ in 0..(s - k) {
        omega = omega.square();
    }
    omega
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2curves::bn256::Fr;

    #[test]
    fn omega_2_to_k_equals_one() {
        for k in 1..6 {
            let mut x = compute_omega(k);
            for _ in 0..k {
                x = x.square();
            }
            assert_eq!(x, Fr::one(), "omega^(2^{k}) must equal 1");
        }
    }

    #[test]
    fn omega_for_k_0_is_one() {
        // 1-element domain → ω = 1.
        assert_eq!(compute_omega(0), Fr::one());
    }
}
