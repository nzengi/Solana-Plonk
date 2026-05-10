//! Fibonacci halo2 circuit.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use halo2curves::ff::Field;

/// Circuit width: number of rows we materialize Fibonacci over. For k=4 we
/// have n = 16 rows; with `BLINDING_FACTORS = 5` halo2 reserves the last
/// 6 rows for blinding, so we can populate at most rows 0..=9. We pick
/// `FIB_LEN = 8` (rows 0..=7) for headroom.
pub const FIB_LEN: usize = 8;

#[derive(Clone, Debug)]
pub struct FibonacciConfig {
    pub a:        Column<Advice>,
    pub q_fib:    Column<Fixed>,
    pub instance: Column<Instance>,
    pub s_fib:    Selector,    // selector that, after halo2 keygen, gets
                                // baked into `q_fib` (so the gate AST sees
                                // a single Fixed query, not a Selector).
}

#[derive(Default, Clone, Debug)]
pub struct FibonacciCircuit {
    pub seed_a: Fr,            // a(0)
    pub seed_b: Fr,            // a(1)
}

impl FibonacciCircuit {
    /// Compute the value at row `FIB_LEN - 1` from the two seeds.
    /// Caller passes this as the public input.
    pub fn target(&self) -> Fr {
        let mut a = self.seed_a;
        let mut b = self.seed_b;
        for _ in 2..FIB_LEN {
            let c = a + b;
            a = b;
            b = c;
        }
        b
    }
}

impl Circuit<Fr> for FibonacciCircuit {
    type Config = FibonacciConfig;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let a        = meta.advice_column();
        let q_fib    = meta.fixed_column();
        let instance = meta.instance_column();
        let s_fib    = meta.selector();

        meta.enable_equality(a);
        meta.enable_equality(instance);

        meta.create_gate("fibonacci", |meta| {
            let s     = meta.query_selector(s_fib);
            let q     = meta.query_fixed(q_fib, Rotation::cur());
            let a_cur = meta.query_advice(a, Rotation::cur());
            let a_nxt = meta.query_advice(a, Rotation::next());
            let a_nn  = meta.query_advice(a, Rotation(2));
            // Rationale for both `s` and `q_fib`: halo2 inlines the selector
            // into a fixed column during keygen via `optimize_phase`, so the
            // verifier only sees the `q_fib` Fixed query in the AST. We use
            // both during configure() to keep halo2's compression heuristic
            // simple.
            vec![s * q * (a_cur + a_nxt - a_nn)]
        });

        FibonacciConfig { a, q_fib, instance, s_fib }
    }

    fn synthesize(
        &self,
        cfg: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let target_cell = layouter.assign_region(
            || "fibonacci sequence",
            |mut region| {
                // Row 0 + 1: seeds.
                let mut a_prev = region.assign_advice(
                    || "a(0)", cfg.a, 0, || Value::known(self.seed_a),
                )?;
                let mut a_cur = region.assign_advice(
                    || "a(1)", cfg.a, 1, || Value::known(self.seed_b),
                )?;

                // Rows 0..FIB_LEN-2: enable the gate. q_fib = 1, selector on.
                // Row FIB_LEN-2: still need the gate to bind a(FIB_LEN-1) to
                // a(FIB_LEN-3) + a(FIB_LEN-2). Actually we want the gate at
                // every row r where rows r, r+1, r+2 are all assigned.
                for row in 0..FIB_LEN - 2 {
                    region.assign_fixed(
                        || "q_fib=1", cfg.q_fib, row, || Value::known(Fr::ONE),
                    )?;
                    cfg.s_fib.enable(&mut region, row)?;
                }

                // Materialize rows 2..FIB_LEN.
                for row in 2..FIB_LEN {
                    let new_value = a_prev.value().copied() + a_cur.value().copied();
                    let new_cell = region.assign_advice(
                        || "a(row)", cfg.a, row, || new_value,
                    )?;
                    a_prev = a_cur;
                    a_cur = new_cell;
                }

                Ok(a_cur)
            },
        )?;

        // Bind the final value to the public input at instance row 0.
        layouter.constrain_instance(target_cell.cell(), cfg.instance, 0)?;
        Ok(())
    }
}

