//! Range-check halo2 circuit using a 4-bit lookup table.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, TableColumn},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

/// 4-bit table → 16 entries.
pub const RC_BITS:       usize = 4;
pub const RC_TABLE_SIZE: usize = 1 << RC_BITS;
/// Number of values to range-check (placed at rows 0..RC_VALUE_COUNT).
pub const RC_VALUE_COUNT: usize = 8;

#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    pub value: Column<Advice>,
    pub table: TableColumn,
}

#[derive(Clone, Debug, Default)]
pub struct RangeCheckCircuit {
    /// Witness values that must each fit in `RC_BITS` bits.
    pub values: [Fr; RC_VALUE_COUNT],
}

impl Circuit<Fr> for RangeCheckCircuit {
    type Config = RangeCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let value = meta.advice_column();
        let table = meta.lookup_table_column();

        meta.lookup("4-bit range", |meta| {
            let v = meta.query_advice(value, Rotation::cur());
            vec![(v, table)]
        });

        RangeCheckConfig { value, table }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        // Load the lookup table: row i has value i, for i in 0..RC_TABLE_SIZE.
        layouter.assign_table(
            || "4-bit table",
            |mut table| {
                for i in 0..RC_TABLE_SIZE {
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

        // Witness assignment for the input values.
        layouter.assign_region(
            || "values",
            |mut region| {
                for (row, v) in self.values.iter().enumerate() {
                    region.assign_advice(
                        || "value",
                        cfg.value,
                        row,
                        || Value::known(*v),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
