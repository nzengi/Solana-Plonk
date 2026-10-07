//! Fully constrained Poseidon permutation chip (BN254, width 3, x^5, Circom
//! constants) — port of `pruv/circuits/src/poseidon_hasher.rs::chip` to halo2 v0.3.0.

use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;
use once_cell::sync::Lazy;

pub const WIDTH: usize = 3;

fn to_ark(f: Fr) -> ark_bn254_04::Fr {
    use ark_ff_04::PrimeField as ArkPF;
    ArkPF::from_le_bytes_mod_order(f.to_repr().as_ref())
}

fn from_ark(f: ark_bn254_04::Fr) -> Fr {
    use ark_ff_04::{BigInteger, PrimeField as ArkPF};
    let le = ArkPF::into_bigint(f).to_bytes_le();
    let mut buf = [0u8; 32];
    buf[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    Fr::from_repr(buf).expect("ark→halo2 field conversion")
}

/// Native Poseidon(a, b), Circom-compatible — the reference the chip is tested against.
pub fn hash_two(a: Fr, b: Fr) -> Fr {
    use light_poseidon::{Poseidon, PoseidonHasher};
    let mut h = Poseidon::<ark_bn254_04::Fr>::new_circom(2).expect("poseidon init");
    from_ark(h.hash(&[to_ark(a), to_ark(b)]).expect("poseidon hash"))
}

pub struct Params {
    pub ark: Vec<Fr>,
    pub mds: Vec<Vec<Fr>>,
    pub full_rounds: usize,
    pub partial_rounds: usize,
}

impl Params {
    #[inline]
    pub fn rounds(&self) -> usize { self.full_rounds + self.partial_rounds }
    #[inline]
    pub fn is_full_round(&self, round: usize) -> bool {
        let half = self.full_rounds / 2;
        round < half || round >= half + self.partial_rounds
    }
}

static PARAMS: Lazy<Params> = Lazy::new(|| {
    let p = light_poseidon::parameters::bn254_x5::get_poseidon_parameters::<ark_bn254_04::Fr>(WIDTH as u8)
        .expect("light-poseidon bn254 x5 width-3 parameters");
    assert_eq!(p.width as usize, WIDTH);
    assert_eq!(p.alpha, 5, "chip gates hard-code the x^5 S-box");
    Params {
        ark: p.ark.iter().map(|x| from_ark(*x)).collect(),
        mds: p.mds.iter().map(|row| row.iter().map(|x| from_ark(*x)).collect()).collect(),
        full_rounds: p.full_rounds,
        partial_rounds: p.partial_rounds,
    }
});

pub fn params() -> &'static Params { &PARAMS }

#[inline]
fn pow5(x: Fr) -> Fr { let x2 = x * x; let x4 = x2 * x2; x4 * x }

/// Full state trace: `trace[0] = [0, a, b]`, `trace[r+1]` = state after round r.
pub fn perm_trace(a: Fr, b: Fr) -> Vec<[Fr; WIDTH]> {
    let p = params();
    let zero = Fr::zero();
    let mut state = [zero, a, b];
    let mut trace = Vec::with_capacity(p.rounds() + 1);
    trace.push(state);
    for round in 0..p.rounds() {
        let mut s = state;
        for i in 0..WIDTH { s[i] += p.ark[round * WIDTH + i]; }
        if p.is_full_round(round) { for v in s.iter_mut() { *v = pow5(*v); } } else { s[0] = pow5(s[0]); }
        let mut next = [zero; WIDTH];
        for i in 0..WIDTH {
            let mut acc = zero;
            for j in 0..WIDTH { acc += s[j] * p.mds[i][j]; }
            next[i] = acc;
        }
        state = next;
        trace.push(state);
    }
    trace
}

#[derive(Clone, Debug)]
pub struct PoseidonConfig {
    /// Round state (3 lanes).
    pub state: [Column<Advice>; WIDTH],
    /// Witnessed S-box outputs: sb_j = (s_j + ark_j)^5 (full rounds, lane 0 of partial rounds)
    /// or sb_j = s_j + ark_j (lanes 1,2 of partial rounds). Witnessing them keeps every
    /// gate expression small, which is what the on-chain verifier pays for.
    pub sb: [Column<Advice>; WIDTH],
    pub ark: [Column<Fixed>; WIDTH],
    pub q_full: Selector,
    pub q_part: Selector,
}

#[derive(Clone, Debug)]
pub struct PoseidonChip { pub config: PoseidonConfig }

impl PoseidonChip {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> PoseidonConfig {
        let state = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        for c in state { meta.enable_equality(c); }
        let sb = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let ark = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        // Complex selectors: they may be summed (`q_full + q_part`) in the MDS gate.
        let q_full = meta.complex_selector();
        let q_part = meta.complex_selector();
        let mds_c: Vec<Vec<Fr>> = params().mds.clone();

        let pow5e = |e: Expression<Fr>| { let e2 = e.clone() * e.clone(); let e4 = e2.clone() * e2; e4 * e };

        // Linear layer, active on every round row: s_next_i = Σ_j MDS_ij · sb_j
        meta.create_gate("poseidon_mds", |meta| {
            let q = meta.query_selector(q_full) + meta.query_selector(q_part);
            let sb_q: Vec<_> = (0..WIDTH).map(|j| meta.query_advice(sb[j], Rotation::cur())).collect();
            let s_next: Vec<_> = (0..WIDTH).map(|i| meta.query_advice(state[i], Rotation::next())).collect();
            (0..WIDTH)
                .map(|i| {
                    let rhs = (0..WIDTH).fold(Expression::Constant(Fr::zero()), |acc, j| {
                        acc + Expression::Constant(mds_c[i][j]) * sb_q[j].clone()
                    });
                    q.clone() * (s_next[i].clone() - rhs)
                })
                .collect::<Vec<_>>()
        });
        // Full round: all three lanes through x^5.
        meta.create_gate("poseidon_sbox_full", |meta| {
            let q = meta.query_selector(q_full);
            (0..WIDTH)
                .map(|j| {
                    let pre = meta.query_advice(state[j], Rotation::cur()) + meta.query_fixed(ark[j], Rotation::cur());
                    let sb_q = meta.query_advice(sb[j], Rotation::cur());
                    q.clone() * (sb_q - pow5e(pre))
                })
                .collect::<Vec<_>>()
        });
        // Partial round: lane 0 through x^5, lanes 1 and 2 pass through.
        meta.create_gate("poseidon_sbox_partial", |meta| {
            let q = meta.query_selector(q_part);
            (0..WIDTH)
                .map(|j| {
                    let pre = meta.query_advice(state[j], Rotation::cur()) + meta.query_fixed(ark[j], Rotation::cur());
                    let sb_q = meta.query_advice(sb[j], Rotation::cur());
                    if j == 0 { q.clone() * (sb_q - pow5e(pre)) } else { q.clone() * (sb_q - pre) }
                })
                .collect::<Vec<_>>()
        });

        PoseidonConfig { state, sb, ark, q_full, q_part }
    }

    pub fn new(config: PoseidonConfig) -> Self { Self { config } }

    /// Lay out one permutation of `(a, b)` at `offset`. Returns
    /// `(capacity_cell, a_cell, b_cell, out_cell)`; the caller must pin
    /// `capacity_cell` to zero (we bind it to a zero public input).
    pub fn assign_permutation(
        &self,
        region: &mut Region<'_, Fr>,
        offset: usize,
        a: Value<Fr>,
        b: Value<Fr>,
    ) -> Result<(AssignedCell<Fr, Fr>, AssignedCell<Fr, Fr>, AssignedCell<Fr, Fr>, AssignedCell<Fr, Fr>), Error> {
        let p = params();
        let cfg = &self.config;
        let rounds = p.rounds();
        let trace = a.zip(b).map(|(a, b)| perm_trace(a, b));

        for r in 0..rounds {
            for i in 0..WIDTH {
                region.assign_fixed(|| "ark", cfg.ark[i], offset + r, || Value::known(p.ark[r * WIDTH + i]))?;
                // S-box witness for this row.
                let full = p.is_full_round(r);
                let sb_v = trace.as_ref().map(|t| {
                    let pre = t[r][i] + p.ark[r * WIDTH + i];
                    if full || i == 0 { pow5(pre) } else { pre }
                });
                region.assign_advice(|| "sb", cfg.sb[i], offset + r, || sb_v)?;
            }
            if p.is_full_round(r) { cfg.q_full.enable(region, offset + r)?; } else { cfg.q_part.enable(region, offset + r)?; }
        }

        let mut first_row: Vec<AssignedCell<Fr, Fr>> = Vec::with_capacity(WIDTH);
        let mut out: Option<AssignedCell<Fr, Fr>> = None;
        for r in 0..=rounds {
            for i in 0..WIDTH {
                let v = trace.as_ref().map(|t| t[r][i]);
                let cell = region.assign_advice(|| "state", cfg.state[i], offset + r, || v)?;
                if r == 0 { first_row.push(cell); } else if r == rounds && i == 0 { out = Some(cell); }
            }
        }
        Ok((first_row[0].clone(), first_row[1].clone(), first_row[2].clone(), out.expect("output cell")))
    }
}
