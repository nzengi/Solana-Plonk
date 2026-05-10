//! BPF benchmark harness for the alt_bn128_g1_msm SIMD proposal.
//!
//! Instruction-data layout: `[mode: u8 | n: u32 LE | scalars… | points…]`.
//!
//!  * mode = 0  →  Pure-BPF arkworks **sequential** scalar_mul + add. This
//!                 is the algorithm a verifier ends up running today *if it
//!                 hand-rolls* MSM in BPF without ever calling the syscall.
//!  * mode = 1  →  Pure-BPF **Pippenger** window-NAF MSM. Same code that
//!                 would land natively if the SIMD activates; BPF execution
//!                 ⪯ native execution, so this is an upper bound on the
//!                 SIMD's achievable cost.
//!  * mode = 2  →  Sequential **`alt_bn128_g1_multiplication_be` + `..._add`
//!                 syscalls**. This is the verifier's actual on-chain path
//!                 today (`shplonk::verify_opening` → `msm_g1`).
//!
//! The `(mode 2) − (mode 1)` gap with mode 1 running natively (i.e. the SIMD
//! proposal's actual configuration) is the headline saving the SIMD delivers.

#![no_std]

extern crate alloc;

use alloc::{vec, vec::Vec};
use g1_msm_ref::{alt_bn128_g1_msm_be, naive_msm_be};

/// Custom error codes surfaced as `ProgramError::Custom`.
pub mod errors {
    pub const MALFORMED_INPUT:   u32 = 0x100;
    pub const UNKNOWN_MODE:      u32 = 0x101;
    pub const REF_IMPL_ERROR:    u32 = 0x200;
    pub const SYSCALL_ERROR:     u32 = 0x300;
}

pub fn run(instruction_data: &[u8]) -> Result<(), u32> {
    if instruction_data.is_empty() {
        return Err(errors::MALFORMED_INPUT);
    }
    let mode = instruction_data[0];
    let payload = &instruction_data[1..];

    match mode {
        0 => {
            // Pure-BPF arkworks naive MSM: per-point scalar_mul + add.
            let _ = naive_msm_be(payload).map_err(|_| errors::REF_IMPL_ERROR)?;
            Ok(())
        }
        1 => {
            // Pure-BPF Pippenger window-NAF MSM.
            let _ = alt_bn128_g1_msm_be(payload).map_err(|_| errors::REF_IMPL_ERROR)?;
            Ok(())
        }
        2 => {
            // Sequential alt_bn128 syscall path — what the verifier does today.
            run_syscall_sequential(payload).map_err(|_| errors::SYSCALL_ERROR)
        }
        _ => Err(errors::UNKNOWN_MODE),
    }
}

/// Mode 2: emulate `shplonk::verify_opening`'s `msm_g1` byte-for-byte —
/// per-point `alt_bn128_g1_multiplication_be`, accumulate via
/// `alt_bn128_g1_addition_be`. Skips zero scalars and identity points
/// just like the real verifier.
fn run_syscall_sequential(payload: &[u8]) -> Result<(), ()> {
    use solana_bn254::prelude::{alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be};

    if payload.len() < 4 {
        return Err(());
    }
    let n = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
    let body = &payload[4..];
    if body.len() != n * 96 {
        return Err(());
    }
    let scalars_end = n * 32;
    let scalars_raw = &body[..scalars_end];
    let points_raw  = &body[scalars_end..];

    let mut acc: Option<[u8; 64]> = None;
    for i in 0..n {
        let scalar: &[u8] = &scalars_raw[i * 32..(i + 1) * 32];
        let point:  &[u8] = &points_raw[i * 64..(i + 1) * 64];

        // Skip the cheap-edge cases the real verifier also skips.
        if scalar.iter().all(|&b| b == 0) || point.iter().all(|&b| b == 0) {
            continue;
        }

        // alt_bn128_g1_multiplication_be wants `[point ‖ scalar]` (96 B).
        let mut mul_in = [0u8; 96];
        mul_in[..64].copy_from_slice(point);
        mul_in[64..].copy_from_slice(scalar);
        let term_vec = alt_bn128_g1_multiplication_be(&mul_in).map_err(|_| ())?;
        let mut term = [0u8; 64];
        term.copy_from_slice(&term_vec);

        acc = Some(match acc {
            None => term,
            Some(prev) => {
                let mut add_in = [0u8; 128];
                add_in[..64].copy_from_slice(&prev);
                add_in[64..].copy_from_slice(&term);
                let sum = alt_bn128_g1_addition_be(&add_in).map_err(|_| ())?;
                let mut out = [0u8; 64];
                out.copy_from_slice(&sum);
                out
            }
        });
    }
    let _ = acc;
    Ok(())
}

#[cfg(feature = "bpf-entrypoint")]
mod entry {
    use pinocchio::{
        account::AccountView, address::Address, entrypoint,
        error::ProgramError, ProgramResult,
    };

    entrypoint!(process_instruction);

    fn process_instruction(
        _program_id: &Address,
        accounts: &mut [AccountView],
        instruction_data: &[u8],
    ) -> ProgramResult {
        // For larger n the input doesn't fit in instruction_data (1232 B tx
        // cap), so we accept the full payload via accounts[0] just like the
        // verifier program does.
        if !accounts.is_empty() {
            let acct = &accounts[0];
            // SAFETY: bench-only, ix has read-only borrow.
            let data: &[u8] = unsafe { acct.borrow_unchecked() };
            return super::run(data).map_err(ProgramError::Custom);
        }
        super::run(instruction_data).map_err(ProgramError::Custom)
    }
}
