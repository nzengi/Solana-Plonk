//! Prover pipeline: SHPLONK + Keccak-BE transcript (what the on-chain verifier reads).

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
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
use halo2_solana_vk_host::{compile_vk, encode::{fr_to_bytes_be, g1_affine_to_bytes_be}};
use standard_plonk_circuit::keccak_be_transcript::{KeccakBeRead, KeccakBeWrite};

use crate::{circuit::CodeIntegrityCircuit, public_inputs};

pub struct CiTestVector {
    pub vk_bytes: Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub kzg_vk: KzgVk,
    pub halo2_vk: VerifyingKey<G1Affine>,
    pub params: ParamsKZG<Bn256>,
    pub instances: [Fr; 4],
    /// Big-endian 32-byte encodings, the order the verifier expects.
    pub public_inputs_be: Vec<[u8; 32]>,
}

/// `srs_path`: a BN254 powers-of-tau file readable by `ParamsKZG::read`; None → insecure seeded setup.
pub fn generate_ci_test_vector(
    k: u32,
    srs_path: Option<&str>,
    program_id: &[u8; 32],
    program_hash: &[u8; 32],
) -> Result<CiTestVector, anyhow::Error> {
    let mut rng = StdRng::from_seed([7u8; 32]);
    let params: ParamsKZG<Bn256> = match srs_path {
        Some(p) => {
            let f = std::fs::File::open(p).map_err(|e| anyhow::anyhow!("open SRS {p}: {e}"))?;
            let mut r = std::io::BufReader::new(f);
            let mut params = ParamsKZG::<Bn256>::read(&mut r).map_err(|e| anyhow::anyhow!("read SRS: {e}"))?;
            anyhow::ensure!(params.k() >= k, "SRS k={} < circuit k={k}", params.k());
            if params.k() > k { params.downsize(k); }
            params
        }
        None => ParamsKZG::<Bn256>::setup(k, &mut rng),
    };

    let instances = public_inputs(program_id, program_hash);
    let circuit = CodeIntegrityCircuit { inputs: Some([instances[0], instances[1], instances[2]]) };

    let vk = keygen_vk(&params, &circuit).map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk = keygen_pk(&params, vk.clone(), &circuit).map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;
    let vk_bytes = compile_vk(&params, &vk).map_err(|e| anyhow::anyhow!("compile_vk: {e:?}"))?;

    // Fifth public input: the zero the capacity lanes are pinned to.
    let mut instance_col: Vec<Fr> = instances.to_vec();
    instance_col.push(Fr::zero());
    let mut writer: Vec<u8> = Vec::new();
    {
        let mut transcript: KeccakBeWrite<&mut Vec<u8>, _, _> = KeccakBeWrite::init(&mut writer);
        let inst: &[&[Fr]] = &[&instance_col];
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            &params, &pk, &[circuit], &[inst], &mut rng, &mut transcript,
        ).map_err(|e| anyhow::anyhow!("create_proof: {e:?}"))?;
        let _: &mut Vec<u8> = transcript.finalize();
    }
    let proof_bytes = writer;

    {
        let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof_bytes.as_slice());
        let inst: &[&[Fr]] = &[&instance_col];
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &pv, &vk, SingleStrategy::new(&pv), &[inst], &mut tr,
        ).map_err(|e| anyhow::anyhow!("halo2 self-verify: {e:?}"))?;
        eprintln!("       ✓ halo2 self-verify (code-integrity, SHPLONK/KeccakBe) passed");
    }

    let g1_one = g1_affine_to_bytes_be(&params.get_g()[0]);
    let kzg_vk = KzgVk {
        g1_one: halo2_solana_verifier::curve::G1(g1_one),
        g2_one: halo2_solana_verifier::curve::G2(g2_affine_to_bytes_be(&params.g2())),
        g2_tau: halo2_solana_verifier::curve::G2(g2_affine_to_bytes_be(&params.s_g2())),
    };
    let public_inputs_be = instance_col.iter().map(fr_to_bytes_be).collect();

    Ok(CiTestVector { vk_bytes, proof_bytes, kzg_vk, halo2_vk: vk, params, instances, public_inputs_be })
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
