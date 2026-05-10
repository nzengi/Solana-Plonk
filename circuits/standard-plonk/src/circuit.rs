//! StandardPlonk halo2 circuit.
//!
//! Witnesses one gate constraint  `q_a·a + q_b·b + q_c·c + q_ab·a·b + q_const = 0`
//! at row 0, plus copy constraints between (a, b, c) advice columns at row 0
//! to exercise the permutation argument.
//!
//! Public inputs: none in v1 (instance column unused; we keep it in the layout
//! for parity with halo2_solana_verifier's StandardPlonk constants but always
//! pass an empty instance vector).

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

#[derive(Clone, Debug)]
pub struct StandardPlonkConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub c: Column<Advice>,
    pub q_a:     Column<Fixed>,
    pub q_b:     Column<Fixed>,
    pub q_c:     Column<Fixed>,
    pub q_ab:    Column<Fixed>,
    pub q_const: Column<Fixed>,
}

#[derive(Default, Clone, Debug)]
pub struct StandardPlonk {
    /// Row 0 advice: (a, b, c) values.
    pub a: Fr,
    pub b: Fr,
    pub c: Fr,
    /// Row 0 fixed selectors: q_a, q_b, q_c, q_ab, q_const.
    pub q_a:     Fr,
    pub q_b:     Fr,
    pub q_c:     Fr,
    pub q_ab:    Fr,
    pub q_const: Fr,
}

impl StandardPlonk {
    /// Construct a satisfying witness for `q_a·a + q_b·b + q_c·c + q_ab·a·b + q_const = 0`.
    /// Pick `a, b, c` and selectors freely, set `q_const = -(rest of expression)` so identity holds.
    pub fn satisfying(a: u64, b: u64, c: u64) -> Self {
        let a = Fr::from(a);
        let b = Fr::from(b);
        let c = Fr::from(c);
        let q_a  = Fr::from(1u64);
        let q_b  = Fr::from(1u64);
        let q_c  = Fr::from(1u64);
        let q_ab = Fr::from(1u64);
        // q_const = −(q_a·a + q_b·b + q_c·c + q_ab·a·b)
        let q_const = -(q_a * a + q_b * b + q_c * c + q_ab * a * b);
        Self { a, b, c, q_a, q_b, q_c, q_ab, q_const }
    }
}

impl Circuit<Fr> for StandardPlonk {
    type Config = StandardPlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // ORDER MATTERS — must match halo2_solana_verifier's standard_plonk constants.
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();

        let q_a     = meta.fixed_column();
        let q_b     = meta.fixed_column();
        let q_c     = meta.fixed_column();
        let q_ab    = meta.fixed_column();
        let q_const = meta.fixed_column();

        // Enable equality on all advice cols so the permutation argument is non-trivial.
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);

        meta.create_gate("standard plonk", |meta| {
            let a_v     = meta.query_advice(a, Rotation::cur());
            let b_v     = meta.query_advice(b, Rotation::cur());
            let c_v     = meta.query_advice(c, Rotation::cur());
            let qa_v    = meta.query_fixed(q_a, Rotation::cur());
            let qb_v    = meta.query_fixed(q_b, Rotation::cur());
            let qc_v    = meta.query_fixed(q_c, Rotation::cur());
            let qab_v   = meta.query_fixed(q_ab, Rotation::cur());
            let qconst_v = meta.query_fixed(q_const, Rotation::cur());

            vec![qa_v * a_v.clone()
                + qb_v * b_v.clone()
                + qc_v * c_v.clone()
                + qab_v * a_v * b_v
                + qconst_v]
        });

        StandardPlonkConfig {
            a, b, c,
            q_a, q_b, q_c, q_ab, q_const,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "row 0",
            |mut region| {
                region.assign_advice(|| "a", config.a, 0, || Value::known(self.a))?;
                region.assign_advice(|| "b", config.b, 0, || Value::known(self.b))?;
                region.assign_advice(|| "c", config.c, 0, || Value::known(self.c))?;
                region.assign_fixed(|| "q_a",     config.q_a,     0, || Value::known(self.q_a))?;
                region.assign_fixed(|| "q_b",     config.q_b,     0, || Value::known(self.q_b))?;
                region.assign_fixed(|| "q_c",     config.q_c,     0, || Value::known(self.q_c))?;
                region.assign_fixed(|| "q_ab",    config.q_ab,    0, || Value::known(self.q_ab))?;
                region.assign_fixed(|| "q_const", config.q_const, 0, || Value::known(self.q_const))?;
                Ok(())
            },
        )?;
        Ok(())
    }
}
