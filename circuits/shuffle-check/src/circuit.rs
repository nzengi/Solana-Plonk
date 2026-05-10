//! Shuffle-check halo2 circuit: assert two advice columns hold the same
//! multiset of values across N rows.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

pub const SH_LEN: usize = 4;

#[derive(Clone, Debug)]
pub struct ShuffleCheckConfig {
    pub input:    Column<Advice>,
    pub shuffled: Column<Advice>,
}

#[derive(Clone, Debug, Default)]
pub struct ShuffleCheckCircuit {
    pub input:    [Fr; SH_LEN],
    pub shuffled: [Fr; SH_LEN],
}

impl Circuit<Fr> for ShuffleCheckCircuit {
    type Config = ShuffleCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let input    = meta.advice_column();
        let shuffled = meta.advice_column();

        meta.shuffle("multiset eq", |meta| {
            let i = meta.query_advice(input,    Rotation::cur());
            let s = meta.query_advice(shuffled, Rotation::cur());
            vec![(i, s)]
        });

        ShuffleCheckConfig { input, shuffled }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "values",
            |mut region| {
                for row in 0..SH_LEN {
                    region.assign_advice(
                        || "input",    cfg.input,    row,
                        || Value::known(self.input[row]),
                    )?;
                    region.assign_advice(
                        || "shuffled", cfg.shuffled, row,
                        || Value::known(self.shuffled[row]),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
