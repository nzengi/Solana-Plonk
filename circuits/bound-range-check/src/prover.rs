//! Off-chain prover for the bound-range-check circuit.

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
use halo2curves::ff::PrimeField;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use sha3::{Digest, Keccak256};

use halo2_solana_verifier::kzg::KzgVk;
use halo2_solana_vk_host::{compile_vk, encode::g1_affine_to_bytes_be};

use standard_plonk_circuit::keccak_be_transcript::{KeccakBeRead, KeccakBeWrite};

use crate::circuit::BoundRangeCheckCircuit;

pub struct BrcTestVector {
    pub vk_bytes:    Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub kzg_vk:      KzgVk,
    pub halo2_vk:    VerifyingKey<G1Affine>,
    pub g2_one:      G2Affine,
    pub g2_tau:      G2Affine,
    pub claimer_hash: Fr,
    pub claimer_hash_be: [u8; 32],
    pub params:      ParamsKZG<Bn256>,
}

/// Compute `claimer_hash = keccak256(claimer_pubkey) reduced into Fr` and
/// return both the field element and its 32-byte BE encoding (which is
/// what the verifier consumes as a public input).
///
/// Reduction strategy: take the 32-byte digest and mask the high byte to
/// `0x1f` (top 3 bits cleared). Since BN254 Fr's MSB is `0x30`, any 32-byte
/// value with MSB ≤ `0x1f` is guaranteed to be a canonical Fr without
/// reaching for explicit modular reduction. Loses 3 bits of entropy per
/// pubkey hash but the demo only needs collision resistance, not full Fr
/// uniformity.
pub fn pubkey_to_claimer_hash(pubkey_bytes: &[u8; 32]) -> (Fr, [u8; 32]) {
    let mut hasher = Keccak256::new();
    hasher.update(pubkey_bytes);
    let mut digest: [u8; 32] = hasher.finalize().into();
    digest[0] &= 0x1f;
    let mut le = digest;
    le.reverse();
    let fr = Fr::from_repr(le)
        .into_option()
        .expect("masked digest must be canonical Fr (top byte ≤ 0x1f < 0x30 = Fr MSB)");
    (fr, digest)
}

pub fn generate_brc_test_vector(
    k: u32,
    seed: [u8; 32],
    payer_pubkey: &[u8; 32],
    x_value: u64,
) -> Result<BrcTestVector, anyhow::Error> {
    let mut rng = StdRng::from_seed(seed);

    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::setup(k, &mut rng);

    let (claimer_hash, claimer_hash_be) = pubkey_to_claimer_hash(payer_pubkey);

    let circuit = BoundRangeCheckCircuit {
        x: Fr::from(x_value),
        claimer_hash,
    };

    let vk: VerifyingKey<G1Affine> = keygen_vk(&params, &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk: ProvingKey<G1Affine>  = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;

    let vk_bytes = compile_vk(&params, &vk)
        .map_err(|e| anyhow::anyhow!("compile_vk: {e:?}"))?;

    let mut writer: Vec<u8> = Vec::new();
    {
        let mut transcript: KeccakBeWrite<&mut Vec<u8>, _, _> = KeccakBeWrite::init(&mut writer);
        let instance_col: &[Fr] = core::slice::from_ref(&claimer_hash);
        let instances: &[&[Fr]] = &[instance_col];
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            &params, &pk, &[circuit], &[instances], &mut rng, &mut transcript,
        ).map_err(|e| anyhow::anyhow!("create_proof: {e:?}"))?;
        let _: &mut Vec<u8> = transcript.finalize();
    }
    let proof_bytes = writer;

    {
        let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof_bytes.as_slice());
        let strategy = SingleStrategy::new(&pv);
        let instance_col: &[Fr] = core::slice::from_ref(&claimer_hash);
        let instances: &[&[Fr]] = &[instance_col];
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &pv, &vk, strategy, &[instances], &mut tr,
        ).map_err(|e| anyhow::anyhow!("halo2 self-verify (bound-range-check, KeccakBe): {e:?}"))?;
        eprintln!("       ✓ halo2 self-verify (bound-range-check, KeccakBe) passed");
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

    Ok(BrcTestVector {
        vk_bytes, proof_bytes, kzg_vk, halo2_vk: vk,
        g2_one: g2_one_aff, g2_tau: g2_tau_aff,
        claimer_hash, claimer_hash_be,
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
