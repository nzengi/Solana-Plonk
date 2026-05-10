//! halo2 `VerifyingKey<G1Affine>`  →  on-chain `PlonkProtocol` byte stream (v1.5).
//!
//! v1.5 emits the extended VK format defined in
//! `halo2_solana_verifier::vk` — gate AST bytecode + query metadata +
//! permuted column type tags. Lookups are unsupported in this version
//! (rejected at compile time).

use halo2_proofs::halo2curves::bn256::{Fr, G1Affine};
use halo2_proofs::plonk::VerifyingKey;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::plonk::Any;
use halo2_proofs::poly::Rotation;

use crate::encode::{fr_to_bytes_be, g1_affine_to_bytes_be, VK_MAGIC, VK_VERSION};
use crate::expression_encoder::{encode_expression, EncodeError};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("halo2 VK could not be compiled into PlonkProtocol: {0}")]
    Compile(&'static str),
    #[error("encoding failure: {0}")]
    Encode(&'static str),
    #[error("gate expression encoding failed: {0:?}")]
    GateEncode(EncodeError),
    #[error("v1.5 does not support lookup arguments — drop them or wait for v2")]
    LookupsUnsupported,
    #[error("v1.5 does not support shuffle arguments — drop them or wait for v2")]
    ShufflesUnsupported,
    #[error("permuted column not found in any *_queries list at Rotation::cur — \
             this VK has copy constraints on a column without a rotation-0 query")]
    PermutedColumnQueryMissing,
}

impl From<EncodeError> for Error {
    fn from(e: EncodeError) -> Self { Error::GateEncode(e) }
}

/// Compile a halo2 (BN254/KZG) verifying key plus its KZG params into the
/// flat on-chain byte format consumed by `halo2_solana_verifier::vk::parse_vk`.
pub fn compile_vk(
    params: &ParamsKZG<halo2curves::bn256::Bn256>,
    vk: &VerifyingKey<G1Affine>,
) -> Result<Vec<u8>, Error> {
    let k = params.k();
    let omega = compute_omega(k);

    let cs = vk.cs();

    // ── reject unsupported features early ────────────────────────────────
    if !cs.lookups().is_empty() {
        return Err(Error::LookupsUnsupported);
    }
    if !cs.shuffles().is_empty() {
        return Err(Error::ShufflesUnsupported);
    }

    let num_instance         = cs.num_instance_columns();
    let num_advice           = cs.num_advice_columns();
    let num_fixed            = cs.num_fixed_columns();
    let cs_degree            = cs.degree();
    let num_advice_queries   = cs.advice_queries().len();
    let num_fixed_queries    = cs.fixed_queries().len();
    let num_instance_queries = cs.instance_queries().len();
    let num_challenges       = cs.num_challenges();
    let blinding_factors     = cs.blinding_factors();

    // Halo2's permutation argument splits perm columns into chunks sized by
    // `chunk_len = cs_degree - 2`. At least 1 chunk if any perm columns exist.
    let perm_columns_vec = cs.permutation().get_columns();
    let perm_columns = perm_columns_vec.len();
    let chunk_len = cs_degree.saturating_sub(2).max(1);
    let num_perm_chunks = if perm_columns == 0 { 0 } else { (perm_columns + chunk_len - 1) / chunk_len };

    let transcript_repr = vk.transcript_repr();
    let transcript_repr_be = fr_to_bytes_be(&transcript_repr);

    let fixed_commits = vk.fixed_commitments();
    let perm_commits  = vk.permutation().commitments();

    // ── pre-encode gate bytecodes ────────────────────────────────────────
    let mut gate_blobs: Vec<Vec<Vec<u8>>> = Vec::with_capacity(cs.gates().len());
    for gate in cs.gates() {
        let mut polys: Vec<Vec<u8>> = Vec::with_capacity(gate.polynomials().len());
        for poly in gate.polynomials() {
            polys.push(encode_expression(poly, cs)?);
        }
        gate_blobs.push(polys);
    }

    // ── pre-resolve permuted column types + query indices ───────────────
    // For each permuted column, find the (column, Rotation::cur()) entry
    // in the matching *_queries list and record its index.
    let mut permuted_meta: Vec<(u8, u32)> = Vec::with_capacity(perm_columns);
    for col in &perm_columns_vec {
        let (col_type, query_index) = match col.column_type() {
            Any::Advice(_) => {
                let idx = cs.advice_queries().iter().position(|(c, r)| {
                    c.index() == col.index() && r.0 == Rotation::cur().0
                }).ok_or(Error::PermutedColumnQueryMissing)?;
                (0u8, idx as u32)
            }
            Any::Fixed => {
                let idx = cs.fixed_queries().iter().position(|(c, r)| {
                    c.index() == col.index() && r.0 == Rotation::cur().0
                }).ok_or(Error::PermutedColumnQueryMissing)?;
                (1u8, idx as u32)
            }
            Any::Instance => {
                let idx = cs.instance_queries().iter().position(|(c, r)| {
                    c.index() == col.index() && r.0 == Rotation::cur().0
                }).ok_or(Error::PermutedColumnQueryMissing)?;
                (2u8, idx as u32)
            }
        };
        permuted_meta.push((col_type, query_index));
    }

    // ── now write the VK byte stream ─────────────────────────────────────
    let mut out = Vec::with_capacity(2048);

    // Header
    out.extend_from_slice(VK_MAGIC);
    out.extend_from_slice(&VK_VERSION.to_le_bytes());

    // Metadata (11 u32 LE fields)
    out.extend_from_slice(&k.to_le_bytes());
    out.extend_from_slice(&(num_instance         as u32).to_le_bytes());
    out.extend_from_slice(&(num_advice           as u32).to_le_bytes());
    out.extend_from_slice(&(num_fixed            as u32).to_le_bytes());
    out.extend_from_slice(&(cs_degree            as u32).to_le_bytes());
    out.extend_from_slice(&(num_advice_queries   as u32).to_le_bytes());
    out.extend_from_slice(&(num_fixed_queries    as u32).to_le_bytes());
    out.extend_from_slice(&(num_instance_queries as u32).to_le_bytes());
    out.extend_from_slice(&(num_challenges       as u32).to_le_bytes());
    out.extend_from_slice(&(blinding_factors     as u32).to_le_bytes());
    out.extend_from_slice(&(num_perm_chunks      as u32).to_le_bytes());

    // omega + transcript_repr
    out.extend_from_slice(&fr_to_bytes_be(&omega));
    out.extend_from_slice(&transcript_repr_be);

    // Query metadata: advice → fixed → instance, each (col_index u32 LE, rotation i32 LE)
    write_queries(&mut out, cs.advice_queries().iter()
        .map(|(c, r)| (c.index() as u32, r.0)));
    write_queries(&mut out, cs.fixed_queries().iter()
        .map(|(c, r)| (c.index() as u32, r.0)));
    write_queries(&mut out, cs.instance_queries().iter()
        .map(|(c, r)| (c.index() as u32, r.0)));

    // Gates AST bytecode
    out.extend_from_slice(&(gate_blobs.len() as u32).to_le_bytes());
    for polys in &gate_blobs {
        out.extend_from_slice(&(polys.len() as u32).to_le_bytes());
        for bc in polys {
            out.extend_from_slice(&(bc.len() as u32).to_le_bytes());
            out.extend_from_slice(bc);
        }
    }

    // Commits
    out.extend_from_slice(&(fixed_commits.len() as u32).to_le_bytes());
    for p in fixed_commits { out.extend_from_slice(&g1_affine_to_bytes_be(p)); }
    out.extend_from_slice(&(perm_commits.len() as u32).to_le_bytes());
    for p in perm_commits  { out.extend_from_slice(&g1_affine_to_bytes_be(p)); }

    // Permuted column types
    out.extend_from_slice(&(permuted_meta.len() as u32).to_le_bytes());
    for (col_type, query_index) in &permuted_meta {
        out.push(*col_type);
        out.extend_from_slice(&query_index.to_le_bytes());
    }

    Ok(out)
}

fn write_queries<I>(out: &mut Vec<u8>, iter: I)
where
    I: IntoIterator<Item = (u32, i32)>,
{
    for (col_index, rotation) in iter {
        out.extend_from_slice(&col_index.to_le_bytes());
        out.extend_from_slice(&rotation.to_le_bytes());
    }
}

/// Compute ω, the primitive 2^k root of unity in BN254 Fr, by squaring
/// `Fr::ROOT_OF_UNITY` (which is a 2^S-th root) the right number of times.
fn compute_omega(k: u32) -> Fr {
    use halo2curves::ff::PrimeField;
    let s = Fr::S;
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
        assert_eq!(compute_omega(0), Fr::one());
    }
}
