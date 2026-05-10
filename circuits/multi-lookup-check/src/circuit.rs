//! Multi-lookup halo2 circuit: 4-bit + 3-bit range checks on two advice
//! columns. Two lookup arguments, two table columns.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, TableColumn},
    poly::Rotation,
};
use halo2curves::bn256::Fr;

pub const ML_LO_BITS:  usize = 4;
pub const ML_HI_BITS:  usize = 3;
pub const ML_LO_SIZE:  usize = 1 << ML_LO_BITS;
pub const ML_HI_SIZE:  usize = 1 << ML_HI_BITS;
pub const ML_LEN:      usize = 8;

#[derive(Clone, Debug)]
pub struct MultiLookupConfig {
    pub lo_value: Column<Advice>,
    pub hi_value: Column<Advice>,
    pub lo_table: TableColumn,
    pub hi_table: TableColumn,
}

#[derive(Clone, Debug, Default)]
pub struct MultiLookupCircuit {
    pub lo_values: [Fr; ML_LEN],
    pub hi_values: [Fr; ML_LEN],
}

impl Circuit<Fr> for MultiLookupCircuit {
    type Config = MultiLookupConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let lo_value = meta.advice_column();
        let hi_value = meta.advice_column();
        let lo_table = meta.lookup_table_column();
        let hi_table = meta.lookup_table_column();

        // Lookup #0: lo_value ∈ lo_table (4-bit)
        meta.lookup("4-bit range (lo)", |meta| {
            let v = meta.query_advice(lo_value, Rotation::cur());
            vec![(v, lo_table)]
        });

        // Lookup #1: hi_value ∈ hi_table (3-bit)
        meta.lookup("3-bit range (hi)", |meta| {
            let v = meta.query_advice(hi_value, Rotation::cur());
            vec![(v, hi_table)]
        });

        MultiLookupConfig { lo_value, hi_value, lo_table, hi_table }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "lo table (4-bit)",
            |mut table| {
                for i in 0..ML_LO_SIZE {
                    table.assign_cell(
                        || "lo entry", cfg.lo_table, i, || Value::known(Fr::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;
        layouter.assign_table(
            || "hi table (3-bit)",
            |mut table| {
                for i in 0..ML_HI_SIZE {
                    table.assign_cell(
                        || "hi entry", cfg.hi_table, i, || Value::known(Fr::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        layouter.assign_region(
            || "values",
            |mut region| {
                for row in 0..ML_LEN {
                    region.assign_advice(
                        || "lo", cfg.lo_value, row, || Value::known(self.lo_values[row]),
                    )?;
                    region.assign_advice(
                        || "hi", cfg.hi_value, row, || Value::known(self.hi_values[row]),
                    )?;
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
