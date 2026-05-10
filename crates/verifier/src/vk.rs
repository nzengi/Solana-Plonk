//! On-chain `VerifyingKey` byte format.
//!
//! Layout (packed binary). BN254 field elements are 32-byte big-endian
//! (matches `alt_bn128_*_be`); metadata u32 fields are little-endian (matches
//! Solana convention).
//!
//! ```text
//! magic              : [u8; 8]     = b"H2SV0001"
//! version            : u32 LE       = 1
//! k                  : u32 LE       // log2 of circuit rows
//! num_instance       : u32 LE
//! num_advice         : u32 LE
//! num_fixed          : u32 LE
//! cs_degree          : u32 LE       // ConstraintSystem::degree()
//! num_advice_queries : u32 LE
//! num_fixed_queries  : u32 LE
//! blinding_factors   : u32 LE
//! num_perm_chunks    : u32 LE
//! omega              : [u8; 32]     // BN254 Fr, BE — primitive 2^k root of unity
//! transcript_repr    : [u8; 32]     // pre-computed Blake2b("Halo2-Verify-Key" || …)
//! n_fixed            : u32 LE
//! fixed[]            : [u8; 64*n_fixed]   // G1Affine BE (x ‖ y)
//! n_perm             : u32 LE
//! perm[]             : [u8; 64*n_perm]    // G1Affine BE (x ‖ y)
//! ```
//!
//! Total size for a v1 Standard PLONK circuit (k=4, ~5 fixed cols, 1 perm col):
//! 8 + 40 + 64 + 4 + 5*64 + 4 + 1*64 = ~504 bytes — embeds as `const` in BPF
//! rodata trivially.
//!
//! See `halo2-solana-vk-host::compile::compile_vk` for the matching encoder.

use alloc::vec::Vec;

use crate::{curve::G1, plonk::PlonkProtocol, Error};

pub const VK_MAGIC: &[u8; 8] = b"H2SV0001";
pub const VK_VERSION: u32 = 1;

pub fn parse_vk(bytes: &[u8]) -> Result<PlonkProtocol, Error> {
    let mut r = Reader::new(bytes);

    let magic = r.read_array::<8>()?;
    if &magic != VK_MAGIC {
        return Err(Error::InvalidVkEncoding);
    }
    let version = r.read_u32_le()?;
    if version != VK_VERSION {
        return Err(Error::InvalidVkEncoding);
    }

    let k                  = r.read_u32_le()?;
    let num_instance       = r.read_u32_le()? as usize;
    let num_advice         = r.read_u32_le()? as usize;
    let num_fixed          = r.read_u32_le()? as usize;
    let cs_degree          = r.read_u32_le()? as usize;
    let num_advice_queries = r.read_u32_le()? as usize;
    let num_fixed_queries  = r.read_u32_le()? as usize;
    let blinding_factors   = r.read_u32_le()? as usize;
    let num_perm_chunks    = r.read_u32_le()? as usize;

    let omega_bytes = r.read_array::<32>()?;
    let omega = crate::field::fr_from_bytes_be(&omega_bytes)?;

    let transcript_repr = r.read_array::<32>()?;

    let n_fixed = r.read_u32_le()? as usize;
    let mut fixed_commitments = Vec::with_capacity(n_fixed);
    for _ in 0..n_fixed {
        fixed_commitments.push(G1(r.read_array::<64>()?));
    }

    let n_perm = r.read_u32_le()? as usize;
    let mut permutation_commitments = Vec::with_capacity(n_perm);
    for _ in 0..n_perm {
        permutation_commitments.push(G1(r.read_array::<64>()?));
    }

    if !r.is_empty() {
        return Err(Error::InvalidVkEncoding);
    }

    // Sanity check: n_fixed must equal num_fixed + num_advice columns'
    // selector commitments — but PSE-Halo2's `fixed_commitments` already
    // includes both fixed columns and selector commitments in one vec, so
    // we don't enforce equality here. The verifier uses `n_fixed` directly.
    let _ = (num_instance, num_advice, num_fixed);

    Ok(PlonkProtocol {
        k,
        omega,
        num_instance,
        num_advice,
        num_fixed,
        cs_degree,
        num_advice_queries,
        num_fixed_queries,
        blinding_factors,
        num_perm_chunks,
        fixed_commitments,
        permutation_commitments,
        transcript_repr,
    })
}

// ---------------------------------------------------------------------------
// Reader helper — bounds-checked byte-by-byte parser.
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self { Self { buf, pos: 0 } }

    fn is_empty(&self) -> bool { self.pos == self.buf.len() }

    fn ensure(&self, n: usize) -> Result<(), Error> {
        if self.pos.checked_add(n).map_or(true, |end| end > self.buf.len()) {
            Err(Error::InvalidVkEncoding)
        } else { Ok(()) }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.ensure(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_u32_le(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn synth_empty_vk_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(VK_MAGIC);
        buf.extend_from_slice(&VK_VERSION.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());          // k
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_instance
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_advice
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_fixed
        buf.extend_from_slice(&3u32.to_le_bytes());          // cs_degree
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_advice_queries
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_fixed_queries
        buf.extend_from_slice(&0u32.to_le_bytes());          // blinding_factors
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_perm_chunks
        let mut omega = [0u8; 32]; omega[31] = 1;
        buf.extend_from_slice(&omega);                       // omega = 1
        buf.extend_from_slice(&[0u8; 32]);                   // transcript_repr
        buf.extend_from_slice(&0u32.to_le_bytes());          // n_fixed
        buf.extend_from_slice(&0u32.to_le_bytes());          // n_perm
        buf
    }

    /// Smallest possible valid VK: zero columns, zero commitments. Round-trip
    /// confirms the framing (magic/version/lengths/no-trailing-bytes).
    #[test]
    fn round_trip_empty_vk() {
        let buf = synth_empty_vk_bytes();
        let proto = parse_vk(&buf).unwrap();
        assert_eq!(proto.k, 4);
        assert_eq!(proto.num_instance, 0);
        assert_eq!(proto.cs_degree, 3);
        assert_eq!(proto.num_advice_queries, 0);
        assert_eq!(proto.fixed_commitments.len(), 0);
        assert_eq!(proto.permutation_commitments.len(), 0);
        assert_eq!(proto.transcript_repr, [0u8; 32]);
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = b"BADMAGIC".to_vec();
        assert!(matches!(parse_vk(&buf), Err(Error::InvalidVkEncoding)));
    }

    #[test]
    fn rejects_bad_version() {
        let mut buf = Vec::new();
        buf.extend_from_slice(VK_MAGIC);
        buf.extend_from_slice(&999u32.to_le_bytes());
        // Truncated, but we should fail on version before reading further.
        assert!(matches!(parse_vk(&buf), Err(Error::InvalidVkEncoding)));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut buf = synth_empty_vk_bytes();
        buf.push(0xFF); // trailing junk
        assert!(matches!(parse_vk(&buf), Err(Error::InvalidVkEncoding)));
    }
}
