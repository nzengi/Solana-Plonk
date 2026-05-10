//! Off-chain prover pipeline for the Fibonacci circuit, mirroring
//! `standard-plonk-circuit::prover` but with one instance value (the
//! Fibonacci target) and a different gate AST.

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

use crate::circuit::FibonacciCircuit;

pub struct FibTestVector {
    pub vk_bytes:    Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub kzg_vk:      KzgVk,
    pub halo2_vk:    VerifyingKey<G1Affine>,
    pub g2_one:      G2Affine,
    pub g2_tau:      G2Affine,
    pub target:      Fr,                // public input
}

pub fn generate_fib_test_vector(k: u32, seed: [u8; 32]) -> Result<FibTestVector, anyhow::Error> {
    let mut rng = StdRng::from_seed(seed);

    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::setup(k, &mut rng);

    let circuit = FibonacciCircuit { seed_a: Fr::from(1u64), seed_b: Fr::from(1u64) };
    let target = circuit.target();

    let vk: VerifyingKey<G1Affine> = keygen_vk(&params, &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk: ProvingKey<G1Affine>  = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;

    let vk_bytes = compile_vk(&params, &vk)
        .map_err(|e| anyhow::anyhow!("compile_vk: {e:?}"))?;

    let mut writer: Vec<u8> = Vec::new();
    {
        let mut transcript: KeccakBeWrite<&mut Vec<u8>, _, _> = KeccakBeWrite::init(&mut writer);
        let instance_col: &[Fr] = core::slice::from_ref(&target);
        let instances: &[&[Fr]] = &[instance_col];
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
        let instance_col: &[Fr] = core::slice::from_ref(&target);
        let instances: &[&[Fr]] = &[instance_col];
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &pv, &vk, strategy, &[instances], &mut tr,
        ).map_err(|e| anyhow::anyhow!("halo2 self-verify (KeccakBe): {e:?}"))?;
        eprintln!("       ✓ halo2 self-verify (Fibonacci, KeccakBe) passed");
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

    Ok(FibTestVector {
        vk_bytes, proof_bytes, kzg_vk, halo2_vk: vk,
        g2_one: g2_one_aff, g2_tau: g2_tau_aff, target,
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
