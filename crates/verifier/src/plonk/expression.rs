//! Generic gate expression bytecode + RPN evaluator (v1.5).
//!
//! v1 hard-coded the StandardPlonk gate identity directly in
//! `plonk::verifier::gate_standard_plonk`. v1.5 supports any halo2
//! `ConstraintSystem::gates()` by serialising each `Expression<Fr>` into a
//! compact stack-bytecode format that the on-chain verifier evaluates with a
//! single forward pass over a `Vec<Fr>` stack.
//!
//! ## Bytecode format
//!
//! Reverse-Polish (postfix). Each instruction is one tag byte followed by
//! an operand of fixed size depending on the opcode:
//!
//! ```text
//! 0x00  OP_CONST     + [u8; 32]  — push BE Fr constant
//! 0x01  OP_ADVICE    + u32 LE    — push advice_evals[idx]
//! 0x02  OP_FIXED     + u32 LE    — push fixed_evals[idx]
//! 0x03  OP_INSTANCE  + u32 LE    — push instance_evals[idx]
//! 0x04  OP_CHALLENGE + u8        — push user_challenges[idx]
//! 0x05  OP_NEG                   — pop a, push −a
//! 0x06  OP_ADD                   — pop a, pop b, push b + a
//! 0x07  OP_MUL                   — pop a, pop b, push b · a
//! 0x08  OP_SCALE     + [u8; 32]  — pop a, push a · c (c = BE Fr constant)
//! ```
//!
//! Halo2's `Selector(Selector)` variant is intentionally absent from the
//! verifier's bytecode: halo2's `optimize_phase` strips selectors during
//! key-generation by inlining them into the gate polynomials, so by
//! verification time every gate expression is in `Expression::Constant /
//! Fixed / Advice / Instance / Challenge / Sum / Product / Scaled / Negated`
//! — exactly the ops above.
//!
//! ## Soundness
//!
//! The evaluator is a forward pass with no branching on input scalar values,
//! so it inherits the constant-time property of arkworks Fr arithmetic. It
//! never reads outside the bytes / evals slices it's handed, and rejects
//! truncated bytecode + stack underflow + out-of-bounds query indices with
//! `Error::InvalidGateBytecode`.

use alloc::vec::Vec;
use ark_bn254::Fr;

use crate::{field::fr_from_bytes_be, Error};

pub const OP_CONST:     u8 = 0x00;
pub const OP_ADVICE:    u8 = 0x01;
pub const OP_FIXED:     u8 = 0x02;
pub const OP_INSTANCE:  u8 = 0x03;
pub const OP_CHALLENGE: u8 = 0x04;
pub const OP_NEG:       u8 = 0x05;
pub const OP_ADD:       u8 = 0x06;
pub const OP_MUL:       u8 = 0x07;
pub const OP_SCALE:     u8 = 0x08;

/// All the per-evaluation values the bytecode can reference.
pub struct EvalContext<'a> {
    pub advice_evals:    &'a [Fr],
    pub fixed_evals:     &'a [Fr],
    pub instance_evals:  &'a [Fr],
    pub user_challenges: &'a [Fr],
}

/// Run the bytecode with the provided eval context and return the top-of-stack
/// value. Errors out on stack underflow, stack-not-singleton-at-end, OOB query
/// index, malformed Fr constant, or any unknown opcode.
pub fn evaluate(bytecode: &[u8], ctx: &EvalContext<'_>) -> Result<Fr, Error> {
    let mut stack: Vec<Fr> = Vec::with_capacity(16);
    let mut cur = 0usize;

    while cur < bytecode.len() {
        let op = bytecode[cur];
        cur += 1;
        match op {
            OP_CONST => {
                let bytes = read_32(bytecode, &mut cur)?;
                stack.push(fr_from_bytes_be(&bytes)?);
            }
            OP_ADVICE => {
                let idx = read_u32(bytecode, &mut cur)? as usize;
                let v = ctx.advice_evals.get(idx)
                    .ok_or(Error::InvalidGateBytecode)?;
                stack.push(*v);
            }
            OP_FIXED => {
                let idx = read_u32(bytecode, &mut cur)? as usize;
                let v = ctx.fixed_evals.get(idx)
                    .ok_or(Error::InvalidGateBytecode)?;
                stack.push(*v);
            }
            OP_INSTANCE => {
                let idx = read_u32(bytecode, &mut cur)? as usize;
                let v = ctx.instance_evals.get(idx)
                    .ok_or(Error::InvalidGateBytecode)?;
                stack.push(*v);
            }
            OP_CHALLENGE => {
                let idx = read_u8(bytecode, &mut cur)? as usize;
                let v = ctx.user_challenges.get(idx)
                    .ok_or(Error::InvalidGateBytecode)?;
                stack.push(*v);
            }
            OP_NEG => {
                let a = stack.pop().ok_or(Error::InvalidGateBytecode)?;
                stack.push(-a);
            }
            OP_ADD => {
                let a = stack.pop().ok_or(Error::InvalidGateBytecode)?;
                let b = stack.pop().ok_or(Error::InvalidGateBytecode)?;
                stack.push(b + a);
            }
            OP_MUL => {
                let a = stack.pop().ok_or(Error::InvalidGateBytecode)?;
                let b = stack.pop().ok_or(Error::InvalidGateBytecode)?;
                stack.push(b * a);
            }
            OP_SCALE => {
                let bytes = read_32(bytecode, &mut cur)?;
                let c = fr_from_bytes_be(&bytes)?;
                let a = stack.pop().ok_or(Error::InvalidGateBytecode)?;
                stack.push(a * c);
            }
            _ => return Err(Error::InvalidGateBytecode),
        }
    }

    if stack.len() != 1 {
        return Err(Error::InvalidGateBytecode);
    }
    Ok(stack.pop().unwrap())
}

#[inline]
fn read_u8(b: &[u8], cur: &mut usize) -> Result<u8, Error> {
    if *cur >= b.len() { return Err(Error::InvalidGateBytecode); }
    let v = b[*cur];
    *cur += 1;
    Ok(v)
}

#[inline]
fn read_u32(b: &[u8], cur: &mut usize) -> Result<u32, Error> {
    if cur.checked_add(4).map_or(true, |e| e > b.len()) {
        return Err(Error::InvalidGateBytecode);
    }
    let v = u32::from_le_bytes([b[*cur], b[*cur+1], b[*cur+2], b[*cur+3]]);
    *cur += 4;
    Ok(v)
}

#[inline]
fn read_32(b: &[u8], cur: &mut usize) -> Result<[u8; 32], Error> {
    if cur.checked_add(32).map_or(true, |e| e > b.len()) {
        return Err(Error::InvalidGateBytecode);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[*cur..*cur + 32]);
    *cur += 32;
    Ok(out)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::field::fr_to_bytes_be;
    use ark_ff::Field;

    fn empty_ctx() -> EvalContext<'static> {
        EvalContext {
            advice_evals:    &[],
            fixed_evals:     &[],
            instance_evals:  &[],
            user_challenges: &[],
        }
    }

    fn ctx_with<'a>(advice: &'a [Fr], fixed: &'a [Fr]) -> EvalContext<'a> {
        EvalContext {
            advice_evals: advice,
            fixed_evals: fixed,
            instance_evals: &[],
            user_challenges: &[],
        }
    }

    fn push_const(b: &mut Vec<u8>, v: Fr) {
        b.push(OP_CONST);
        b.extend_from_slice(&fr_to_bytes_be(&v));
    }
    fn push_advice(b: &mut Vec<u8>, idx: u32) {
        b.push(OP_ADVICE);
        b.extend_from_slice(&idx.to_le_bytes());
    }
    fn push_fixed(b: &mut Vec<u8>, idx: u32) {
        b.push(OP_FIXED);
        b.extend_from_slice(&idx.to_le_bytes());
    }
    fn push_scale(b: &mut Vec<u8>, c: Fr) {
        b.push(OP_SCALE);
        b.extend_from_slice(&fr_to_bytes_be(&c));
    }

    #[test]
    fn const_alone() {
        let mut bc = Vec::new();
        push_const(&mut bc, Fr::from(42u64));
        assert_eq!(evaluate(&bc, &empty_ctx()).unwrap(), Fr::from(42u64));
    }

    #[test]
    fn add_two_constants() {
        // 3 + 5 = 8
        let mut bc = Vec::new();
        push_const(&mut bc, Fr::from(3u64));
        push_const(&mut bc, Fr::from(5u64));
        bc.push(OP_ADD);
        assert_eq!(evaluate(&bc, &empty_ctx()).unwrap(), Fr::from(8u64));
    }

    #[test]
    fn mul_then_add() {
        // (2 * 3) + 1 = 7
        let mut bc = Vec::new();
        push_const(&mut bc, Fr::from(2u64));
        push_const(&mut bc, Fr::from(3u64));
        bc.push(OP_MUL);
        push_const(&mut bc, Fr::from(1u64));
        bc.push(OP_ADD);
        assert_eq!(evaluate(&bc, &empty_ctx()).unwrap(), Fr::from(7u64));
    }

    #[test]
    fn neg_and_scale() {
        // (-7) * 5 = -35
        let mut bc = Vec::new();
        push_const(&mut bc, Fr::from(7u64));
        bc.push(OP_NEG);
        push_scale(&mut bc, Fr::from(5u64));
        assert_eq!(evaluate(&bc, &empty_ctx()).unwrap(), -Fr::from(35u64));
    }

    #[test]
    fn standard_plonk_gate() {
        // q_a*a + q_b*b + q_c*c + q_ab*a*b + q_const
        // advice = [a=5, b=11, c=99]
        // fixed  = [q_a=3, q_b=7, q_c=0, q_ab=0, q_const=100]
        // expected = 3*5 + 7*11 + 0 + 0 + 100 = 192
        let advice = [Fr::from(5u64), Fr::from(11u64), Fr::from(99u64)];
        let fixed  = [Fr::from(3u64), Fr::from(7u64), Fr::from(0u64),
                      Fr::from(0u64), Fr::from(100u64)];

        let mut bc = Vec::new();
        push_fixed(&mut bc, 0);  push_advice(&mut bc, 0); bc.push(OP_MUL);  // q_a*a
        push_fixed(&mut bc, 1);  push_advice(&mut bc, 1); bc.push(OP_MUL);  // q_b*b
        bc.push(OP_ADD);                                                    // +
        push_fixed(&mut bc, 2);  push_advice(&mut bc, 2); bc.push(OP_MUL);  // q_c*c
        bc.push(OP_ADD);                                                    // +
        push_fixed(&mut bc, 3);
        push_advice(&mut bc, 0); push_advice(&mut bc, 1); bc.push(OP_MUL); // a*b
        bc.push(OP_MUL);                                                    // q_ab*a*b
        bc.push(OP_ADD);                                                    // +
        push_fixed(&mut bc, 4);                                             // q_const
        bc.push(OP_ADD);                                                    // +

        let r = evaluate(&bc, &ctx_with(&advice, &fixed)).unwrap();
        assert_eq!(r, Fr::from(192u64));
    }

    #[test]
    fn rejects_stack_underflow() {
        let bc = vec![OP_ADD];  // ADD with empty stack
        assert!(matches!(evaluate(&bc, &empty_ctx()), Err(Error::InvalidGateBytecode)));
    }

    #[test]
    fn rejects_stack_residue() {
        // Two pushes, no consumer → stack ends with 2 items
        let mut bc = Vec::new();
        push_const(&mut bc, Fr::from(1u64));
        push_const(&mut bc, Fr::from(2u64));
        assert!(matches!(evaluate(&bc, &empty_ctx()), Err(Error::InvalidGateBytecode)));
    }

    #[test]
    fn rejects_oob_query_index() {
        let mut bc = Vec::new();
        push_advice(&mut bc, 99);  // advice[99] doesn't exist
        let advice = [Fr::ONE; 3];
        assert!(matches!(
            evaluate(&bc, &ctx_with(&advice, &[])),
            Err(Error::InvalidGateBytecode)
        ));
    }

    #[test]
    fn rejects_truncated_operand() {
        let bc = vec![OP_CONST, 0xFF, 0xFF];   // OP_CONST expects 32 bytes
        assert!(matches!(evaluate(&bc, &empty_ctx()), Err(Error::InvalidGateBytecode)));
    }

    #[test]
    fn rejects_unknown_opcode() {
        let bc = vec![0xEF];
        assert!(matches!(evaluate(&bc, &empty_ctx()), Err(Error::InvalidGateBytecode)));
    }

    /// OP_CHALLENGE pushes user_challenges[idx] onto the stack — verifies
    /// the v2.0 user-defined phase challenges path. Single-phase circuits
    /// pass `proof.user_challenges` populated by `read_proof` (squeezed
    /// after advice batch, before theta).
    #[test]
    fn op_challenge_pushes_user_challenge() {
        // bc: CHALLENGE 0  (push user_challenges[0])
        let bc = vec![OP_CHALLENGE, 0u8];
        let ctx = EvalContext {
            advice_evals:    &[],
            fixed_evals:     &[],
            instance_evals:  &[],
            user_challenges: &[Fr::from(13u64), Fr::from(17u64)],
        };
        assert_eq!(evaluate(&bc, &ctx).unwrap(), Fr::from(13u64));
    }

    /// OP_CHALLENGE with idx 1 picks the second challenge — confirms
    /// indexing is correct for >1 user challenge.
    #[test]
    fn op_challenge_indexed() {
        let bc = vec![OP_CHALLENGE, 1u8];
        let ctx = EvalContext {
            advice_evals:    &[],
            fixed_evals:     &[],
            instance_evals:  &[],
            user_challenges: &[Fr::from(13u64), Fr::from(17u64)],
        };
        assert_eq!(evaluate(&bc, &ctx).unwrap(), Fr::from(17u64));
    }

    /// Out-of-range challenge index is rejected as invalid bytecode.
    #[test]
    fn op_challenge_oob_rejects() {
        let bc = vec![OP_CHALLENGE, 5u8];
        let ctx = EvalContext {
            advice_evals:    &[],
            fixed_evals:     &[],
            instance_evals:  &[],
            user_challenges: &[Fr::from(13u64)],
        };
        assert!(matches!(evaluate(&bc, &ctx), Err(Error::InvalidGateBytecode)));
    }
}
