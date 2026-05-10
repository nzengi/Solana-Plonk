//! Off-chain pipeline: `ParamsKZG::setup → keygen_vk → keygen_pk → create_proof`.
//!
//! Produces the (vk_bytes, proof_bytes, kzg_vk_bytes) tuple that
//! `halo2_solana_verifier::verify` consumes.

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

use crate::{circuit::StandardPlonk, keccak_be_transcript::{KeccakBeRead, KeccakBeWrite}};

/// Full off-chain pipeline output ready to feed `halo2_solana_verifier::verify`.
pub struct TestVector {
    pub vk_bytes:    Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub kzg_vk:      KzgVk,
    /// Halo2 VK kept around for shadow-verification debugging.
    pub halo2_vk:    VerifyingKey<G1Affine>,
    /// halo2curves G2 generators kept for shadow pairing test.
    pub g2_one:      G2Affine,
    pub g2_tau:      G2Affine,
}

/// Backwards-compatible alias.
pub fn generate_test_vector_with_vk(k: u32, seed: [u8; 32]) -> Result<TestVector, anyhow::Error> {
    generate_test_vector(k, seed)
}

/// Generate a satisfying StandardPlonk witness, prove with Keccak-BE
/// transcript, and emit on-chain-format bytes.
pub fn generate_test_vector(k: u32, seed: [u8; 32]) -> Result<TestVector, anyhow::Error>
where
    // Avoid pulling anyhow into deps — return a String error instead.
{
    let mut rng = StdRng::from_seed(seed);

    // 1. KZG params + structured reference string.
    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::setup(k, &mut rng);

    // 2. Build a satisfying circuit instance.
    let circuit = StandardPlonk::satisfying(3, 5, 7);

    // 3. Keygen.
    let vk: VerifyingKey<G1Affine> = keygen_vk(&params, &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk: ProvingKey<G1Affine>  = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;

    // 4. Compile VK to on-chain bytes.
    let vk_bytes = compile_vk(&params, &vk)
        .map_err(|e| anyhow::anyhow!("compile_vk: {e:?}"))?;

    // 5. Generate proof with Keccak-BE transcript.
    let mut writer: Vec<u8> = Vec::new();
    {
        let mut transcript: KeccakBeWrite<&mut Vec<u8>, _, _> = KeccakBeWrite::init(&mut writer);
        let instances: &[&[Fr]] = &[];
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            &params,
            &pk,
            &[circuit],
            &[instances],
            &mut rng,
            &mut transcript,
        )
        .map_err(|e| anyhow::anyhow!("create_proof: {e:?}"))?;
        let _: &mut Vec<u8> = transcript.finalize();
    }
    let proof_bytes = writer;

    // 5b. Halo2 self-verify with the same KeccakBeRead — confirms the proof is
    //     internally consistent in EvmTranscript byte semantics. This is the
    //     authoritative check that our prover-side transcript is correct;
    //     any failure of our Solana verifier on a self-verified proof is a
    //     bug in our verifier crate, not the prover.
    {
        let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof_bytes.as_slice());
        let strategy = SingleStrategy::new(&pv);
        let instances: &[&[Fr]] = &[];
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &pv, &vk, strategy, &[instances], &mut tr,
        ).map_err(|e| anyhow::anyhow!("halo2 self-verify (KeccakBe round-trip): {e:?}"))?;
        eprintln!("       ✓ halo2 self-verify (KeccakBe transcript) passed");
    }

    // 6. Extract KZG verifying SRS — `[1]_1`, `[1]_2`, `[τ]_2`.
    let g1_one_aff: G1Affine = params.get_g()[0];
    let g1_one_bytes = g1_affine_to_bytes_be(&g1_one_aff);

    let s_g2 = params.s_g2();
    let g2_one_aff = params.g2();
    let g2_one_bytes  = g2_affine_to_bytes_be(&g2_one_aff);
    let g2_tau_bytes  = g2_affine_to_bytes_be(&s_g2);

    let kzg_vk = KzgVk {
        g1_one: halo2_solana_verifier::curve::G1(g1_one_bytes),
        g2_one: halo2_solana_verifier::curve::G2(g2_one_bytes),
        g2_tau: halo2_solana_verifier::curve::G2(g2_tau_bytes),
    };

    Ok(TestVector {
        vk_bytes, proof_bytes, kzg_vk, halo2_vk: vk,
        g2_one: g2_one_aff,
        g2_tau: s_g2,
    })
}

/// Convert a halo2curves G2Affine to BE bytes [x.c1 ‖ x.c0 ‖ y.c1 ‖ y.c0].
/// Matches the layout `solana_bn254::prelude::*_be` consumes.
fn g2_affine_to_bytes_be(p: &halo2curves::bn256::G2Affine) -> [u8; 128] {
    use halo2curves::ff::PrimeField;
    use halo2curves::group::prime::PrimeCurveAffine;
    let mut out = [0u8; 128];
    if bool::from(p.is_identity()) {
        return out;
    }
    // halo2curves Fq2 has fields c0, c1.
    let x = p.x;
    let y = p.y;

    let mut x1 = x.c1.to_repr(); x1.as_mut().reverse(); // LE → BE
    let mut x0 = x.c0.to_repr(); x0.as_mut().reverse();
    let mut y1 = y.c1.to_repr(); y1.as_mut().reverse();
    let mut y0 = y.c0.to_repr(); y0.as_mut().reverse();

    out[..32].copy_from_slice(x1.as_ref());
    out[32..64].copy_from_slice(x0.as_ref());
    out[64..96].copy_from_slice(y1.as_ref());
    out[96..].copy_from_slice(y0.as_ref());
    out
}
