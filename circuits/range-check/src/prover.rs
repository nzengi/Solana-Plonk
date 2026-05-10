//! Off-chain prover pipeline for the 4-bit range-check circuit. No instance
//! column (the lookup table itself is the only constraint), so verification
//! takes an empty public-input list.

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine, G2Affine};
use rand::rngs::StdRng;
use rand_core::SeedableRng;

use halo2_solana_verifier::kzg::KzgVk;
use halo2_solana_vk_host::{compile_vk, encode::g1_affine_to_bytes_be};

use standard_plonk_circuit::keccak_be_transcript::{KeccakBeRead, KeccakBeWrite};

use crate::circuit::{RangeCheckCircuit, RC_VALUE_COUNT};

pub struct RcTestVector {
    pub vk_bytes:    Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub kzg_vk:      KzgVk,
    pub halo2_vk:    VerifyingKey<G1Affine>,
    pub g2_one:      G2Affine,
    pub g2_tau:      G2Affine,
    /// Kept around for the shadow audit (`circuits/range-check/src/shadow.rs`),
    /// which re-runs halo2's verifier on mutated proof bytes.
    pub params:      ParamsKZG<Bn256>,
}

pub fn generate_rc_test_vector(k: u32, seed: [u8; 32]) -> Result<RcTestVector, anyhow::Error> {
    let mut rng = StdRng::from_seed(seed);

    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::setup(k, &mut rng);

    // Witness: 8 values each in 0..16 (well inside the 4-bit table).
    let values: [Fr; RC_VALUE_COUNT] = [
        Fr::from(0u64), Fr::from(1u64), Fr::from(7u64), Fr::from(15u64),
        Fr::from(3u64), Fr::from(9u64), Fr::from(12u64), Fr::from(5u64),
    ];
    let circuit = RangeCheckCircuit { values };

    let vk: VerifyingKey<G1Affine> = keygen_vk(&params, &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk: ProvingKey<G1Affine>  = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;

    let vk_bytes = compile_vk(&params, &vk)
        .map_err(|e| anyhow::anyhow!("compile_vk: {e:?}"))?;

    let mut writer: Vec<u8> = Vec::new();
    {
        let mut transcript: KeccakBeWrite<&mut Vec<u8>, _, _> = KeccakBeWrite::init(&mut writer);
        let instances: &[&[Fr]] = &[];     // no instance columns
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            &params, &pk, &[circuit], &[instances], &mut rng, &mut transcript,
        ).map_err(|e| anyhow::anyhow!("create_proof: {e:?}"))?;
        let _: &mut Vec<u8> = transcript.finalize();
    }
    let proof_bytes = writer;

    // Halo2 self-verify with the same KeccakBe transcript.
    {
        let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof_bytes.as_slice());
        let strategy = SingleStrategy::new(&pv);
        let instances: &[&[Fr]] = &[];
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &pv, &vk, strategy, &[instances], &mut tr,
        ).map_err(|e| anyhow::anyhow!("halo2 self-verify (range-check, KeccakBe): {e:?}"))?;
        eprintln!("       ✓ halo2 self-verify (range-check, KeccakBe) passed");
    }

    let g1_one_aff: G1Affine = params.get_g()[0];
    let g1_one_bytes = g1_affine_to_bytes_be(&g1_one_aff);
    let g2_one_aff = params.g2();
    let g2_tau_aff = params.s_g2();
    let g2_one_bytes = g2_affine_to_bytes_be(&g2_one_aff);
    let g2_tau_bytes = g2_affine_to_bytes_be(&g2_tau_aff);

    let kzg_vk = KzgVk {
        g1_one: halo2_solana_verifier::curve::G1(g1_one_bytes),
        g2_one: halo2_solana_verifier::curve::G2(g2_one_bytes),
        g2_tau: halo2_solana_verifier::curve::G2(g2_tau_bytes),
    };

    Ok(RcTestVector {
        vk_bytes, proof_bytes, kzg_vk, halo2_vk: vk,
        g2_one: g2_one_aff, g2_tau: g2_tau_aff,
        params,
    })
}

fn g2_affine_to_bytes_be(p: &G2Affine) -> [u8; 128] {
    use halo2curves::ff::PrimeField;
    use halo2curves::group::prime::PrimeCurveAffine;
    let mut out = [0u8; 128];
    if bool::from(p.is_identity()) { return out; }
    let mut x1 = p.x.c1.to_repr(); x1.as_mut().reverse();
    let mut x0 = p.x.c0.to_repr(); x0.as_mut().reverse();
    let mut y1 = p.y.c1.to_repr(); y1.as_mut().reverse();
    let mut y0 = p.y.c0.to_repr(); y0.as_mut().reverse();
    out[..32].copy_from_slice(x1.as_ref());
    out[32..64].copy_from_slice(x0.as_ref());
    out[64..96].copy_from_slice(y1.as_ref());
    out[96..].copy_from_slice(y0.as_ref());
    out
}
