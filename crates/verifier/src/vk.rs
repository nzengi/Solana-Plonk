//! On-chain `VerifyingKey` byte format (v2.0).
//!
//! Layout (packed binary). BN254 field elements are 32-byte big-endian
//! (matches `alt_bn128_*_be`); metadata fields are little-endian (matches
//! Solana convention).
//!
//! ```text
//! magic                : [u8; 8]    = b"H2SV0003"
//! version              : u32 LE     = 3
//!
//! ---- circuit metadata ----
//! k                    : u32 LE     // log2 of circuit rows
//! num_instance         : u32 LE     // # of instance columns
//! num_advice           : u32 LE
//! num_fixed            : u32 LE
//! cs_degree            : u32 LE     // ConstraintSystem::degree()
//! num_advice_queries   : u32 LE
//! num_fixed_queries    : u32 LE
//! num_instance_queries : u32 LE     // v1.5: instance column queries
//! num_challenges       : u32 LE     // v1.5: user-defined phase challenges
//! blinding_factors     : u32 LE
//! num_perm_chunks      : u32 LE
//!
//! omega                : [u8; 32]   // BN254 Fr, BE — primitive 2^k root of unity
//! transcript_repr      : [u8; 32]   // pre-computed Blake2b("Halo2-Verify-Key" || …)
//!
//! ---- v1.5 query metadata ----
//! advice_queries[]     : (column_index: u32 LE, rotation: i32 LE) × num_advice_queries
//! fixed_queries[]      : (column_index: u32 LE, rotation: i32 LE) × num_fixed_queries
//! instance_queries[]   : (column_index: u32 LE, rotation: i32 LE) × num_instance_queries
//!
//! ---- v1.5 gates AST bytecode ----
//! num_gates            : u32 LE
//! for each gate:
//!     num_polys        : u32 LE
//!     for each poly:
//!         bytecode_len : u32 LE
//!         bytecode     : [u8; bytecode_len]   // see plonk::expression
//!
//! ---- commits ----
//! n_fixed              : u32 LE
//! fixed[]              : G1Affine × n_fixed   // 64 B BE per point (x ‖ y)
//! n_perm               : u32 LE
//! perm[]               : G1Affine × n_perm
//!
//! ---- v1.5 permuted column types ----
//! n_perm_columns       : u32 LE     // must equal n_perm
//! permuted_columns[]   : (col_type: u8, query_index: u32 LE) × n_perm_columns
//!                        // col_type ∈ {0=advice, 1=fixed, 2=instance}
//!
//! ---- v2.0 lookup arguments ----
//! num_lookups          : u32 LE
//! for each lookup:
//!     num_input_expressions : u32 LE
//!     for each input expr:
//!         bytecode_len      : u32 LE
//!         bytecode          : [u8; bytecode_len]   // RPN, see plonk::expression
//!     num_table_expressions : u32 LE   // must equal num_input_expressions
//!     for each table expr:
//!         bytecode_len      : u32 LE
//!         bytecode          : [u8; bytecode_len]
//!
//! ---- v2.0 shuffle arguments ----
//! num_shuffles         : u32 LE
//! for each shuffle:
//!     num_input_expressions   : u32 LE
//!     <input bytecodes>
//!     num_shuffle_expressions : u32 LE   // must equal num_input_expressions
//!     <shuffle bytecodes>
//! ```
//!
//! See `halo2-solana-vk-host::compile::compile_vk` for the matching encoder.

use alloc::vec::Vec;

use crate::{curve::G1, plonk::{LookupArgument, PlonkProtocol, ShuffleArgument}, Error};

pub const VK_MAGIC: &[u8; 8] = b"H2SV0003";
pub const VK_VERSION: u32 = 3;

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

    // ── circuit metadata ─────────────────────────────────────────────────
    let k                    = r.read_u32_le()?;
    let num_instance         = r.read_u32_le()? as usize;
    let num_advice           = r.read_u32_le()? as usize;
    let num_fixed            = r.read_u32_le()? as usize;
    let cs_degree            = r.read_u32_le()? as usize;
    let num_advice_queries   = r.read_u32_le()? as usize;
    let num_fixed_queries    = r.read_u32_le()? as usize;
    let num_instance_queries = r.read_u32_le()? as usize;
    let num_challenges       = r.read_u32_le()? as usize;
    let blinding_factors     = r.read_u32_le()? as usize;
    let num_perm_chunks      = r.read_u32_le()? as usize;

    let omega_bytes = r.read_array::<32>()?;
    let omega = crate::field::fr_from_bytes_be(&omega_bytes)?;
    let transcript_repr = r.read_array::<32>()?;

    // ── query metadata ──────────────────────────────────────────────────
    let advice_queries   = read_queries(&mut r, num_advice_queries)?;
    let fixed_queries    = read_queries(&mut r, num_fixed_queries)?;
    let instance_queries = read_queries(&mut r, num_instance_queries)?;

    // ── gates AST bytecode ──────────────────────────────────────────────
    let num_gates = r.read_u32_le()? as usize;
    let mut gates: Vec<Vec<Vec<u8>>> = Vec::with_capacity(num_gates);
    for _ in 0..num_gates {
        let num_polys = r.read_u32_le()? as usize;
        let mut polys: Vec<Vec<u8>> = Vec::with_capacity(num_polys);
        for _ in 0..num_polys {
            let bc_len = r.read_u32_le()? as usize;
            polys.push(r.read_bytes(bc_len)?);
        }
        gates.push(polys);
    }

    // ── commits ─────────────────────────────────────────────────────────
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

    // ── permuted column types ──────────────────────────────────────────
    let n_perm_columns = r.read_u32_le()? as usize;
    if n_perm_columns != n_perm {
        return Err(Error::InvalidVkEncoding);
    }
    let mut permuted_columns: Vec<(u8, u32)> = Vec::with_capacity(n_perm_columns);
    for _ in 0..n_perm_columns {
        let col_type = r.read_array::<1>()?[0];
        if col_type > 2 {
            return Err(Error::InvalidVkEncoding);
        }
        let query_index = r.read_u32_le()?;
        permuted_columns.push((col_type, query_index));
    }

    // ── v2.0 lookup arguments ──────────────────────────────────────────
    let num_lookups = r.read_u32_le()? as usize;
    let mut lookups: Vec<LookupArgument> = Vec::with_capacity(num_lookups);
    for _ in 0..num_lookups {
        let input_count = r.read_u32_le()? as usize;
        let mut input_expressions: Vec<Vec<u8>> = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let bc_len = r.read_u32_le()? as usize;
            input_expressions.push(r.read_bytes(bc_len)?);
        }
        let table_count = r.read_u32_le()? as usize;
        if table_count != input_count {
            // Halo2 enforces matched input/table column count.
            return Err(Error::InvalidVkEncoding);
        }
        let mut table_expressions: Vec<Vec<u8>> = Vec::with_capacity(table_count);
        for _ in 0..table_count {
            let bc_len = r.read_u32_le()? as usize;
            table_expressions.push(r.read_bytes(bc_len)?);
        }
        lookups.push(LookupArgument { input_expressions, table_expressions });
    }

    // ── v2.0 shuffle arguments ─────────────────────────────────────────
    let num_shuffles = r.read_u32_le()? as usize;
    let mut shuffles: Vec<ShuffleArgument> = Vec::with_capacity(num_shuffles);
    for _ in 0..num_shuffles {
        let input_count = r.read_u32_le()? as usize;
        let mut input_expressions: Vec<Vec<u8>> = Vec::with_capacity(input_count);
        for _ in 0..input_count {
            let bc_len = r.read_u32_le()? as usize;
            input_expressions.push(r.read_bytes(bc_len)?);
        }
        let shuf_count = r.read_u32_le()? as usize;
        if shuf_count != input_count {
            return Err(Error::InvalidVkEncoding);
        }
        let mut shuffle_expressions: Vec<Vec<u8>> = Vec::with_capacity(shuf_count);
        for _ in 0..shuf_count {
            let bc_len = r.read_u32_le()? as usize;
            shuffle_expressions.push(r.read_bytes(bc_len)?);
        }
        shuffles.push(ShuffleArgument { input_expressions, shuffle_expressions });
    }

    if !r.is_empty() {
        return Err(Error::InvalidVkEncoding);
    }

    Ok(PlonkProtocol {
        k,
        omega,
        num_instance,
        num_advice,
        num_fixed,
        cs_degree,
        num_advice_queries,
        num_fixed_queries,
        num_instance_queries,
        num_challenges,
        blinding_factors,
        num_perm_chunks,
        fixed_commitments,
        permutation_commitments,
        advice_queries,
        fixed_queries,
        instance_queries,
        gates,
        permuted_columns,
        lookups,
        shuffles,
        transcript_repr,
    })
}

#[inline]
fn read_queries(r: &mut Reader<'_>, count: usize) -> Result<Vec<(u32, i32)>, Error> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let col = r.read_u32_le()?;
        let rot = r.read_i32_le()?;
        out.push((col, rot));
    }
    Ok(out)
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

    fn read_i32_le(&mut self) -> Result<i32, Error> {
        Ok(i32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        self.ensure(n)?;
        let out = self.buf[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    fn synth_empty_vk_bytes() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(VK_MAGIC);
        buf.extend_from_slice(&VK_VERSION.to_le_bytes());
        // 11 metadata u32 fields all zero except k=4 and cs_degree=3:
        buf.extend_from_slice(&4u32.to_le_bytes());          // k
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_instance
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_advice
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_fixed
        buf.extend_from_slice(&3u32.to_le_bytes());          // cs_degree
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_advice_queries
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_fixed_queries
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_instance_queries
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_challenges
        buf.extend_from_slice(&0u32.to_le_bytes());          // blinding_factors
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_perm_chunks
        let mut omega = [0u8; 32]; omega[31] = 1;
        buf.extend_from_slice(&omega);                       // omega = 1
        buf.extend_from_slice(&[0u8; 32]);                   // transcript_repr
        // empty query lists
        // empty gates
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_gates
        // empty commits
        buf.extend_from_slice(&0u32.to_le_bytes());          // n_fixed
        buf.extend_from_slice(&0u32.to_le_bytes());          // n_perm
        buf.extend_from_slice(&0u32.to_le_bytes());          // n_perm_columns
        // v2.0 footers
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_lookups
        buf.extend_from_slice(&0u32.to_le_bytes());          // num_shuffles
        buf
    }

    /// Round-trip an empty VK — confirms the framing parses end-to-end.
    #[test]
    fn round_trip_empty_vk() {
        let buf = synth_empty_vk_bytes();
        let proto = parse_vk(&buf).unwrap();
        assert_eq!(proto.k, 4);
        assert_eq!(proto.num_instance, 0);
        assert_eq!(proto.cs_degree, 3);
        assert_eq!(proto.num_advice_queries, 0);
        assert_eq!(proto.num_instance_queries, 0);
        assert_eq!(proto.num_challenges, 0);
        assert!(proto.advice_queries.is_empty());
        assert!(proto.gates.is_empty());
        assert!(proto.permuted_columns.is_empty());
        assert_eq!(proto.fixed_commitments.len(), 0);
        assert_eq!(proto.permutation_commitments.len(), 0);
        assert_eq!(proto.transcript_repr, [0u8; 32]);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = synth_empty_vk_bytes();
        buf[0] = b'X';
        assert!(matches!(parse_vk(&buf), Err(Error::InvalidVkEncoding)));
    }

    #[test]
    fn rejects_bad_version() {
        let mut buf = synth_empty_vk_bytes();
        buf[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(parse_vk(&buf), Err(Error::InvalidVkEncoding)));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut buf = synth_empty_vk_bytes();
        buf.push(0xFF);
        assert!(matches!(parse_vk(&buf), Err(Error::InvalidVkEncoding)));
    }

    #[test]
    fn rejects_perm_count_mismatch() {
        let mut buf = synth_empty_vk_bytes();
        // n_perm_columns is the last u32 BEFORE the v2.0 footers
        // (num_lookups + num_shuffles = 8 trailing bytes). Bump it to 1
        // without supplying an entry → parser must reject.
        let off = buf.len() - 12;
        buf[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(parse_vk(&buf), Err(Error::InvalidVkEncoding)));
    }
}
