//! Encode halo2's `Expression<Fr>` into the verifier's RPN bytecode format.
//!
//! Mirrors the opcodes defined in `halo2-solana-verifier::plonk::expression`.
//! The encoder walks the halo2 AST in post-order, emitting each node's
//! opcode + operand. The output is consumed by the on-chain bytecode
//! evaluator with O(depth) stack space.

use halo2_proofs::plonk::{ConstraintSystem, Expression};
use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;

// Opcode constants — must match `halo2-solana-verifier::plonk::expression::OP_*`.
pub const OP_CONST:     u8 = 0x00;
pub const OP_ADVICE:    u8 = 0x01;
pub const OP_FIXED:     u8 = 0x02;
pub const OP_INSTANCE:  u8 = 0x03;
pub const OP_CHALLENGE: u8 = 0x04;
pub const OP_NEG:       u8 = 0x05;
pub const OP_ADD:       u8 = 0x06;
pub const OP_MUL:       u8 = 0x07;
pub const OP_SCALE:     u8 = 0x08;

/// Errors that can arise while encoding a halo2 `Expression`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// `Expression::Selector(_)` survived past `optimize_phase`. Halo2's
    /// keygen normally inlines selectors; if one shows up at this layer the
    /// VK was constructed wrong (or the user mutated a `VerifyingKey`).
    SelectorPresent,
    /// `Expression::Advice/Fixed/Instance` had no resolved query index.
    /// Halo2 sets `query.index = Some(...)` during keygen via `query_cells`;
    /// a `None` here means the gate wasn't normalized.
    UnresolvedQueryIndex,
}

/// Encode a single `Expression<Fr>` to RPN bytecode.
///
/// `cs` is needed to resolve query column-index + rotation back into the
/// flat `query_index` halo2 stores in its `*_queries()` lists. Halo2 v0.3
/// keeps the resolved query indices in private `index: Option<usize>`
/// fields on `AdviceQuery`/`FixedQuery`/`InstanceQuery`, so we re-derive
/// them here by linear scan over `cs.advice_queries()` etc. (Constant
/// time per query relative to circuit size; circuits with > a few dozen
/// queries are rare in practice.)
pub fn encode_expression(
    expr: &Expression<Fr>,
    cs: &ConstraintSystem<Fr>,
) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::with_capacity(64);
    walk(expr, cs, &mut out)?;
    Ok(out)
}

fn walk(
    expr: &Expression<Fr>,
    cs: &ConstraintSystem<Fr>,
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    match expr {
        Expression::Constant(c) => {
            out.push(OP_CONST);
            out.extend_from_slice(&fr_to_be(c));
        }
        Expression::Selector(_) => {
            return Err(EncodeError::SelectorPresent);
        }
        Expression::Fixed(query) => {
            let col = query.column_index();
            let rot = query.rotation().0;
            let idx = cs.fixed_queries().iter()
                .position(|(c, r)| c.index() == col && r.0 == rot)
                .ok_or(EncodeError::UnresolvedQueryIndex)?;
            out.push(OP_FIXED);
            out.extend_from_slice(&(idx as u32).to_le_bytes());
        }
        Expression::Advice(query) => {
            let col = query.column_index();
            let rot = query.rotation().0;
            let idx = cs.advice_queries().iter()
                .position(|(c, r)| c.index() == col && r.0 == rot)
                .ok_or(EncodeError::UnresolvedQueryIndex)?;
            out.push(OP_ADVICE);
            out.extend_from_slice(&(idx as u32).to_le_bytes());
        }
        Expression::Instance(query) => {
            let col = query.column_index();
            let rot = query.rotation().0;
            let idx = cs.instance_queries().iter()
                .position(|(c, r)| c.index() == col && r.0 == rot)
                .ok_or(EncodeError::UnresolvedQueryIndex)?;
            out.push(OP_INSTANCE);
            out.extend_from_slice(&(idx as u32).to_le_bytes());
        }
        Expression::Challenge(challenge) => {
            let idx = challenge.index();
            if idx > u8::MAX as usize {
                return Err(EncodeError::UnresolvedQueryIndex);
            }
            out.push(OP_CHALLENGE);
            out.push(idx as u8);
        }
        Expression::Negated(a) => {
            walk(a, cs, out)?;
            out.push(OP_NEG);
        }
        Expression::Sum(a, b) => {
            walk(a, cs, out)?;
            walk(b, cs, out)?;
            out.push(OP_ADD);
        }
        Expression::Product(a, b) => {
            walk(a, cs, out)?;
            walk(b, cs, out)?;
            out.push(OP_MUL);
        }
        Expression::Scaled(a, c) => {
            walk(a, cs, out)?;
            out.push(OP_SCALE);
            out.extend_from_slice(&fr_to_be(c));
        }
    }
    Ok(())
}

#[inline]
fn fr_to_be(v: &Fr) -> [u8; 32] {
    let mut le = v.to_repr();
    le.as_mut().reverse();
    let mut be = [0u8; 32];
    be.copy_from_slice(le.as_ref());
    be
}

// Unit tests of `encode_expression` would require constructing a
// `ConstraintSystem<Fr>`, which halo2 does not expose externally. The
// real validation lives in the integration path: `compile_vk` consuming
// `circuits/standard-plonk` + `circuits/fibonacci` → `parse_vk` →
// verifier evaluator. See `tests::regression_*` in those crates.
