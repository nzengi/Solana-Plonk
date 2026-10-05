use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2curves::bn256::Fr;

use crate::poseidon::{PoseidonChip, PoseidonConfig};

/// No separate input columns: the inputs live in the first row of each
/// permutation's state columns and are bound to the instance column directly.
/// That keeps the permutation argument to 3 advice + 1 instance column.
#[derive(Clone, Debug)]
pub struct CodeIntegrityConfig {
    pub instance: Column<Instance>,
    pub poseidon: PoseidonConfig,
}

/// Witness: the three field inputs (None for keygen).
#[derive(Clone, Default)]
pub struct CodeIntegrityCircuit {
    pub inputs: Option<[Fr; 3]>,
}

impl Circuit<Fr> for CodeIntegrityCircuit {
    type Config = CodeIntegrityConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self { inputs: None } }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let poseidon = PoseidonChip::configure(meta);
        CodeIntegrityConfig { instance, poseidon }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let (pid_v, lo_v, hi_v) = match &self.inputs {
            Some([p, l, h]) => (Value::known(*p), Value::known(*l), Value::known(*h)),
            None => (Value::unknown(), Value::unknown(), Value::unknown()),
        };
        let chip = PoseidonChip::new(config.poseidon.clone());
        // Instance rows: 0 program_id, 1 hash_lo, 2 hash_hi, 3 commitment, 4 zero (capacity pin).
        let (cap1, pid_cell, lo_cell, inner) =
            layouter.assign_region(|| "poseidon-1", |mut region| chip.assign_permutation(&mut region, 0, pid_v, lo_v))?;
        let inner_v = inner.value().copied();
        let (cap2, hi_cell, commit) = layouter.assign_region(
            || "poseidon-2",
            |mut region| {
                let (cap, a_cell, b_cell, out) = chip.assign_permutation(&mut region, 0, inner_v, hi_v)?;
                region.constrain_equal(inner.cell(), a_cell.cell())?;
                Ok((cap, b_cell, out))
            },
        )?;
        layouter.constrain_instance(pid_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(lo_cell.cell(), config.instance, 1)?;
        layouter.constrain_instance(hi_cell.cell(), config.instance, 2)?;
        layouter.constrain_instance(commit.cell(), config.instance, 3)?;
        layouter.constrain_instance(cap1.cell(), config.instance, 4)?;
        layouter.constrain_instance(cap2.cell(), config.instance, 4)?;
        Ok(())
    }
}
