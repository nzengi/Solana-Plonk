//! External-circuit compatibility test (Tier A3).
//!
//! Ports snark-verifier-sdk's `examples/standard_plonk.rs` StandardPlonk
//! variant verbatim. Differs from our `circuits/standard-plonk/` in two
//! ways that exercise verifier code paths we hadn't covered:
//!
//! 1. Adds a 1-wide **instance column** that the gate queries via
//!    `meta.query_instance(instance, Rotation::cur())` — first time a
//!    gate AST contains `Expression::Instance` in our test corpus.
//!    Fibonacci has an instance column but only via `constrain_instance`
//!    (no in-gate query).
//! 2. The gate is `q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0`
//!    — five fixed-coefficient terms plus an instance-column term.
//!
//! Source: vendor/snark-verifier/snark-verifier-sdk/examples/standard_plonk.rs
//! (Axiom team's example). Not part of any halo2-lib library, but a
//! representative "third-party halo2 v0.3.0 circuit" with the right
//! complexity for an MVP compat check.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
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

#[derive(Clone, Copy)]
pub struct ExternalSpConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,
    q_a: Column<Fixed>,
    q_b: Column<Fixed>,
    q_c: Column<Fixed>,
    q_ab: Column<Fixed>,
    constant: Column<Fixed>,
    instance: Column<Instance>,
}

impl ExternalSpConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let [a, b, c] = [(); 3].map(|_| meta.advice_column());
        let [q_a, q_b, q_c, q_ab, constant] = [(); 5].map(|_| meta.fixed_column());
        let instance = meta.instance_column();

        [a, b, c].map(|c| meta.enable_equality(c));
        meta.enable_equality(instance);

        meta.create_gate(
            "q_a·a + q_b·b + q_c·c + q_ab·a·b + constant + instance = 0",
            |meta| {
                let [a, b, c] =
                    [a, b, c].map(|col| meta.query_advice(col, Rotation::cur()));
                let [q_a, q_b, q_c, q_ab, constant] = [q_a, q_b, q_c, q_ab, constant]
                    .map(|col| meta.query_fixed(col, Rotation::cur()));
                let inst = meta.query_instance(instance, Rotation::cur());
                vec![
                    q_a * a.clone()
                        + q_b * b.clone()
                        + q_c * c
                        + q_ab * a * b
                        + constant
                        + inst,
                ]
            },
        );

        ExternalSpConfig { a, b, c, q_a, q_b, q_c, q_ab, constant, instance }
    }
}

#[derive(Clone, Default)]
pub struct ExternalSpCircuit(pub Fr);

impl Circuit<Fr> for ExternalSpCircuit {
    type Config = ExternalSpConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        meta.set_minimum_degree(4);
        ExternalSpConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "",
            |mut region| {
                // Row 0: a = self.0 (= public input), q_a = -1
                //   gate: -1·self.0 + 0 + 0 + 0 + 0 + self.0 = 0 ✓
                region.assign_advice(|| "", config.a, 0, || Value::known(self.0))?;
                region.assign_fixed(|| "", config.q_a, 0, || Value::known(-Fr::ONE))?;
                // Row 1: a = -5, all coefficients = 1..5, no instance value at row 1
                //   gate: 1·(-5) + 2·0 + 3·0 + 4·0 + 5 + 0 = 0 ✓
                region.assign_advice(|| "", config.a, 1, || Value::known(-Fr::from(5u64)))?;
                for (idx, column) in (1..).zip([
                    config.q_a, config.q_b, config.q_c, config.q_ab, config.constant,
                ]) {
                    region.assign_fixed(
                        || "", column, 1, || Value::known(Fr::from(idx as u64)),
                    )?;
                }
                // Row 2: copy 1 across a/b/c (permutation argument exercise).
                let a = region.assign_advice(|| "", config.a, 2, || Value::known(Fr::ONE))?;
                a.copy_advice(|| "", &mut region, config.b, 3)?;
                a.copy_advice(|| "", &mut region, config.c, 4)?;
                Ok(())
            },
        )
    }
}

pub struct ExternalSpTestVector {
    pub vk_bytes:    Vec<u8>,
    pub proof_bytes: Vec<u8>,
    pub kzg_vk:      KzgVk,
    pub instance_value: Fr,
}

/// End-to-end prover pipeline mirroring `circuits/fibonacci/src/prover.rs`.
pub fn generate_test_vector(k: u32, seed: [u8; 32]) -> Result<ExternalSpTestVector, anyhow::Error> {
    let mut rng = StdRng::from_seed(seed);

    let params: ParamsKZG<Bn256> = ParamsKZG::<Bn256>::setup(k, &mut rng);

    // Pick a fixed instance value so the test is reproducible.
    let instance_value = Fr::from(0x4242_4242u64);
    let circuit = ExternalSpCircuit(instance_value);

    let vk: VerifyingKey<G1Affine> = keygen_vk(&params, &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_vk: {e:?}"))?;
    let pk: ProvingKey<G1Affine>  = keygen_pk(&params, vk.clone(), &circuit)
        .map_err(|e| anyhow::anyhow!("keygen_pk: {e:?}"))?;

    let vk_bytes = compile_vk(&params, &vk)
        .map_err(|e| anyhow::anyhow!("compile_vk: {e:?}"))?;
    eprintln!("       compile_vk OK: {} B", vk_bytes.len());

    let instance_col: &[Fr] = core::slice::from_ref(&instance_value);
    let instances: &[&[Fr]] = &[instance_col];

    let mut writer: Vec<u8> = Vec::new();
    {
        let mut transcript: KeccakBeWrite<&mut Vec<u8>, _, _> = KeccakBeWrite::init(&mut writer);
        create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
            &params, &pk, &[circuit], &[instances], &mut rng, &mut transcript,
        ).map_err(|e| anyhow::anyhow!("create_proof: {e:?}"))?;
        let _: &mut Vec<u8> = transcript.finalize();
    }
    let proof_bytes = writer;

    // halo2 self-verify to sanity-check before our verifier.
    {
        let pv: ParamsVerifierKZG<Bn256> = params.verifier_params().clone();
        let mut tr: KeccakBeRead<&[u8], _, _> = KeccakBeRead::init(proof_bytes.as_slice());
        let strategy = SingleStrategy::new(&pv);
        verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
            &pv, &vk, strategy, &[instances], &mut tr,
        ).map_err(|e| anyhow::anyhow!("halo2 self-verify: {e:?}"))?;
        eprintln!("       halo2 self-verify OK");
    }

    let g1_one_aff: G1Affine = params.get_g()[0];
    let g1_one_bytes = g1_affine_to_bytes_be(&g1_one_aff);
    let g2_one_bytes = g2_affine_to_bytes_be(&params.g2());
    let g2_tau_bytes = g2_affine_to_bytes_be(&params.s_g2());

    let kzg_vk = KzgVk {
        g1_one: halo2_solana_verifier::curve::G1(g1_one_bytes),
        g2_one: halo2_solana_verifier::curve::G2(g2_one_bytes),
        g2_tau: halo2_solana_verifier::curve::G2(g2_tau_bytes),
    };

    Ok(ExternalSpTestVector { vk_bytes, proof_bytes, kzg_vk, instance_value })
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
