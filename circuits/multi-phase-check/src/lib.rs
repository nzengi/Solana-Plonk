//! Tier A4 multi-phase test circuit.
//!
//! Shape:
//!   * advice column `a` in **FirstPhase** (phase 0)
//!   * advice column `b` in **SecondPhase** (phase 1)
//!   * 1 fixed selector `q`
//!   * 1 user challenge `r` usable after FirstPhase advice commits
//!   * gate: `q · (r · a + b) = 0`
//!
//! Synthesis assigns a = 0 and b = 0 everywhere → gate trivially holds
//! for any value of `r`. The point is purely to drive the verifier's new
//! phase-interleaved Fiat–Shamir loop:
//!
//! ```text
//!   phase 0: read advice[a]
//!   phase 0: squeeze r
//!   phase 1: read advice[b]
//! ```
//!
//! VK byte layout includes the v2.1 multi-phase appendix
//! (`num_phases=2`, `advice_column_phase=[0,1]`, `challenge_phase=[0]`).

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Challenge, Circuit, Column,
        ConstraintSystem, Error, FirstPhase, Fixed, ProvingKey, SecondPhase, Selector,
        VerifyingKey,
    },
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG, ParamsVerifierKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        Rotation,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use halo2curves::bn256::{Bn256, Fr, G1Affine, G2Affine};
use halo2curves::ff::Field;
use rand::rngs::StdRng;
use rand_core::SeedableRng;

use halo2_solana_verifier::kzg::KzgVk;
use halo2_solana_vk_host::{compile_vk, encode::g1_affine_to_bytes_be};
use standard_plonk_circuit::keccak_be_transcript::{KeccakBeRead, KeccakBeWrite};

pub const MP_LEN: usize = 4;

#[derive(Clone, Debug)]
pub struct MpConfig {
    pub a:     Column<Advice>,   // FirstPhase
    pub b:     Column<Advice>,   // SecondPhase
    pub q:     Column<Fixed>,
    pub s_sel: Selector,
    pub r:     Challenge,        // usable after FirstPhase
}

#[derive(Clone, Debug, Default)]
pub struct MpCircuit;

impl Circuit<Fr> for MpCircuit {
    type Config = MpConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let a     = meta.advice_column_in(FirstPhase);
        let b     = meta.advice_column_in(SecondPhase);
        let q     = meta.fixed_column();
        let s_sel = meta.selector();
        let r     = meta.challenge_usable_after(FirstPhase);

        meta.create_gate("q · (r·a + b) = 0", |meta| {
            let s     = meta.query_selector(s_sel);
            let q_v   = meta.query_fixed(q, Rotation::cur());
            let a_v   = meta.query_advice(a, Rotation::cur());
            let b_v   = meta.query_advice(b, Rotation::cur());
            let r_v   = meta.query_challenge(r);
            vec![s * q_v * (r_v * a_v + b_v)]
        });

        MpConfig { a, b, q, s_sel, r }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "all-zero a + b",
            |mut region| {
                for row in 0..MP_LEN {
                    region.assign_advice(|| "a", cfg.a, row, || Value::known(Fr::ZERO))?;
                    region.assign_advice(|| "b", cfg.b, row, || Value::known(Fr::ZERO))?;
                    region.assign_fixed(|| "q=1", cfg.q, row, || Value::known(Fr::ONE))?;
                    cfg.s_sel.enable(&mut region, row)?;
                }
                Ok(())
            },
        )
    }
}

pub struct MpTestVector {
    pub vk_bytes:    Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub kzg_vk:      KzgVk,
}

pub fn generate_mp_test_vector(k: u32, seed: [u8; 32]) -> Result<MpTestVector, anyhow::Error> {
    let mut rng = StdRng::from_seed(seed);
    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::setup(k, &mut rng);

    let circuit = MpCircuit;
    let vk: VerifyingKey<G1Affine> = keygen_vk(&params, &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk: ProvingKey<G1Affine>  = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;

    let vk_bytes = compile_vk(&params, &vk)
        .map_err(|e| anyhow::anyhow!("compile_vk: {e:?}"))?;
    eprintln!("       compile_vk OK: {} B (with v2.1 multi-phase appendix)", vk_bytes.len());

    let mut writer: Vec<u8> = Vec::new();
    {
        let mut transcript: KeccakBeWrite<&mut Vec<u8>, _, _> = KeccakBeWrite::init(&mut writer);
        let instances: &[&[Fr]] = &[];
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            &params, &pk, &[circuit], &[instances], &mut rng, &mut transcript,
        ).map_err(|e| anyhow::anyhow!("create_proof: {e:?}"))?;
        let _: &mut Vec<u8> = transcript.finalize();
    }
    let proof_bytes = writer;

    // halo2 self-verify with KeccakBe transcript — must pass before we hand
    // the bytes to our Solana verifier.
    {
        let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof_bytes.as_slice());
        let strategy = SingleStrategy::new(&pv);
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &pv, &vk, strategy, &[&[][..]], &mut tr,
        ).map_err(|e| anyhow::anyhow!("halo2 self-verify (multi-phase): {e:?}"))?;
        eprintln!("       halo2 self-verify OK");
    }

    let g1_one_bytes = g1_affine_to_bytes_be(&params.get_g()[0]);
    let g2_one_bytes = g2_affine_to_bytes_be(&params.g2());
    let g2_tau_bytes = g2_affine_to_bytes_be(&params.s_g2());

    let kzg_vk = KzgVk {
        g1_one: halo2_solana_verifier::curve::G1(g1_one_bytes),
        g2_one: halo2_solana_verifier::curve::G2(g2_one_bytes),
        g2_tau: halo2_solana_verifier::curve::G2(g2_tau_bytes),
    };

    Ok(MpTestVector { vk_bytes, proof_bytes, kzg_vk })
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
