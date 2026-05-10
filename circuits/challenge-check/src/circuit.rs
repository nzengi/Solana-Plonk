//! Single-phase challenge halo2 circuit.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Challenge, Circuit, Column, ConstraintSystem, Error, FirstPhase, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use halo2curves::ff::Field;

pub const CH_LEN: usize = 4;

#[derive(Clone, Debug)]
pub struct ChallengeCheckConfig {
    pub a:        Column<Advice>,
    pub q_sel:    Column<Fixed>,
    pub s_sel:    Selector,
    pub r:        Challenge,
}

#[derive(Clone, Debug, Default)]
pub struct ChallengeCheckCircuit;

impl Circuit<Fr> for ChallengeCheckCircuit {
    type Config = ChallengeCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let a     = meta.advice_column();
        let q_sel = meta.fixed_column();
        let s_sel = meta.selector();
        // Phase-0 challenge: usable after FirstPhase advice commits.
        let r = meta.challenge_usable_after(FirstPhase);

        meta.create_gate("q · r · a = 0", |meta| {
            let s = meta.query_selector(s_sel);
            let q = meta.query_fixed(q_sel, Rotation::cur());
            let a_cur = meta.query_advice(a, Rotation::cur());
            let r_v   = meta.query_challenge(r);
            // Gate holds for any r because a = 0 on every active row.
            vec![s * q * (r_v * a_cur)]
        });

        ChallengeCheckConfig { a, q_sel, s_sel, r }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "all-zero a",
            |mut region| {
                for row in 0..CH_LEN {
                    region.assign_advice(
                        || "a", cfg.a, row, || Value::known(Fr::ZERO),
                    )?;
                    region.assign_fixed(
                        || "q_sel=1", cfg.q_sel, row, || Value::known(Fr::ONE),
                    )?;
                    cfg.s_sel.enable(&mut region, row)?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
