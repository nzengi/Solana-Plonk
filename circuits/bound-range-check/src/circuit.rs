//! Bound-range-check halo2 circuit: 4-bit range Plookup + claimer-hash binding.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, TableColumn},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

/// 4-bit table → 16 entries.
pub const BRC_BITS:       usize = 4;
pub const BRC_TABLE_SIZE: usize = 1 << BRC_BITS;

#[derive(Clone, Debug)]
pub struct BoundRangeCheckConfig {
    pub x:        Column<Advice>,
    pub bind:     Column<Advice>,
    pub table:    TableColumn,
    pub instance: Column<Instance>,
}

#[derive(Clone, Debug, Default)]
pub struct BoundRangeCheckCircuit {
    /// Witness value (kept private). MUST be in `[0, BRC_TABLE_SIZE)`.
    pub x: Fr,
    /// Public claimer hash. The same value is published as
    /// `public_inputs[0]` to the verifier. Inside the circuit it is
    /// copy-constrained to `bind[0]`.
    pub claimer_hash: Fr,
}

impl Circuit<Fr> for BoundRangeCheckCircuit {
    type Config = BoundRangeCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let x        = meta.advice_column();
        let bind     = meta.advice_column();
        let table    = meta.lookup_table_column();
        let instance = meta.instance_column();

        meta.enable_equality(bind);
        meta.enable_equality(instance);

        meta.lookup("4-bit range", |meta| {
            let v = meta.query_advice(x, Rotation::cur());
            vec![(v, table)]
        });

        BoundRangeCheckConfig { x, bind, table, instance }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Load the 4-bit lookup table.
        layouter.assign_table(
            || "4-bit table",
            |mut table| {
                for i in 0..BRC_TABLE_SIZE {
                    table.assign_cell(
                        || "table entry",
                        cfg.table,
                        i,
                        || Value::known(Fr::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        // Witness assignment: row 0 holds the private x and the public
        // claimer_hash binding cell.
        let bind_cell = layouter.assign_region(
            || "bound claim",
            |mut region| {
                region.assign_advice(
                    || "x (private)",
                    cfg.x,
                    0,
                    || Value::known(self.x),
                )?;
                let bind_cell = region.assign_advice(
                    || "claimer_hash binding",
                    cfg.bind,
                    0,
                    || Value::known(self.claimer_hash),
                )?;
                Ok(bind_cell)
            },
        )?;

        // Copy-constrain the binding cell to instance[0]. The verifier
        // reconstructs instance evaluations from the public_inputs Vec
        // via Lagrange basis, so this enforces
        //   `bind_advice[0] == public_inputs[0]`.
        layouter.constrain_instance(bind_cell.cell(), cfg.instance, 0)?;
        Ok(())
    }
}
