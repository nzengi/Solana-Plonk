//! Keccak-256 BE transcript matching PSE snark-verifier's `EvmTranscript` and
//! our on-chain `halo2_solana_verifier::transcript::Keccak256Transcript`
//! byte-for-byte.
//!
//! Algorithm (paraphrased — same as our verifier):
//!
//! ```text
//! state := empty Vec<u8>            // grows as bytes are absorbed
//! common_scalar(s)  : state ‖= be32(s)             // reverses LE→BE
//! common_point(p)   : state ‖= be32(p.x) ‖ be32(p.y)
//! squeeze_challenge():
//!     padded = state ‖ (if |state| == 32 then [0x01] else [])
//!     hash   = keccak256(padded)
//!     state := hash
//!     return Challenge255(hash || zeros to 64 bytes)
//! ```
//!
//! The proof bytes layout mirrors what halo2's `create_proof` emits but with
//! BE byte ordering for points and scalars. This matches the ENTIRE protocol
//! sequence consumed by `halo2_solana_verifier::plonk::proof_reader::read_proof`.

use halo2_proofs::transcript::{
    Challenge255, EncodedChallenge, Transcript, TranscriptRead, TranscriptReadBuffer,
    TranscriptWrite, TranscriptWriterBuffer,
};
use halo2curves::{
    ff::{FromUniformBytes, PrimeField},
    Coordinates, CurveAffine,
};
use sha3::{Digest, Keccak256};
use std::io::{self, Read, Write};
use std::marker::PhantomData;

/// Keccak-256 transcript writer with BIG-ENDIAN byte format.
pub struct KeccakBeWrite<W: Write, C: CurveAffine, E: EncodedChallenge<C>> {
    state:  Vec<u8>,
    writer: W,
    _ph:    PhantomData<(C, E)>,
}

impl<W, C> TranscriptWriterBuffer<W, C, Challenge255<C>> for KeccakBeWrite<W, C, Challenge255<C>>
where
    W: Write,
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]> + FromUniformBytes<64>,
    C::Base:   PrimeField<Repr = [u8; 32]>,
{
    fn init(writer: W) -> Self {
        Self { state: Vec::new(), writer, _ph: PhantomData }
    }
    fn finalize(self) -> W {
        self.writer
    }
}

impl<W, C> Transcript<C, Challenge255<C>> for KeccakBeWrite<W, C, Challenge255<C>>
where
    W: Write,
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]> + FromUniformBytes<64>,
    C::Base:   PrimeField<Repr = [u8; 32]>,
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        // Domain-separation byte 0x01 if state is exactly 32 bytes.
        let mut input = self.state.clone();
        if input.len() == 32 {
            input.push(0x01);
        }
        let hash: [u8; 32] = Keccak256::digest(&input).into();
        self.state.clear();
        self.state.extend_from_slice(&hash);

        // Challenge255 expects a 64-byte uniform input. Zero-extend the BE
        // hash so the reduction is `hash mod Fr` (same as our on-chain
        // verifier's `Fr::from_be_bytes_mod_order`).
        // Important: Challenge255::new takes raw bytes and reduces via
        // FromUniformBytes — so to get `hash_be mod Fr`, we reverse to LE
        // first then zero-pad to 64-byte LE little-endian.
        let mut le_padded = [0u8; 64];
        for (i, b) in hash.iter().rev().enumerate() {
            le_padded[i] = *b;
        }
        Challenge255::<C>::new(&le_padded)
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        let coords = Option::<Coordinates<C>>::from(point.coordinates()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "transcript: identity point")
        })?;
        // halo2curves to_repr() is canonical LE; reverse to BE.
        let mut x = coords.x().to_repr();
        let mut y = coords.y().to_repr();
        x.as_mut().reverse();
        y.as_mut().reverse();
        self.state.extend_from_slice(x.as_ref());
        self.state.extend_from_slice(y.as_ref());
        Ok(())
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        let mut data = scalar.to_repr();
        data.as_mut().reverse(); // LE → BE
        self.state.extend_from_slice(data.as_ref());
        Ok(())
    }
}

impl<W, C> TranscriptWrite<C, Challenge255<C>> for KeccakBeWrite<W, C, Challenge255<C>>
where
    W: Write,
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]> + FromUniformBytes<64>,
    C::Base:   PrimeField<Repr = [u8; 32]>,
{
    fn write_point(&mut self, point: C) -> io::Result<()> {
        // Absorb into state first (same algorithm as common_point).
        Transcript::<C, Challenge255<C>>::common_point(self, point)?;
        // Then write the BE-encoded coordinates to the proof byte stream.
        let coords = Option::<Coordinates<C>>::from(point.coordinates()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "transcript: identity point")
        })?;
        let mut x = coords.x().to_repr();
        let mut y = coords.y().to_repr();
        x.as_mut().reverse();
        y.as_mut().reverse();
        self.writer.write_all(x.as_ref())?;
        self.writer.write_all(y.as_ref())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        Transcript::<C, Challenge255<C>>::common_scalar(self, scalar)?;
        let mut data = scalar.to_repr();
        data.as_mut().reverse();
        self.writer.write_all(data.as_ref())
    }
}

// =============================================================================
// READER side — mirrors KeccakBeWrite. Used by gen-proof's halo2 self-verify
// step to confirm the proof is internally consistent in EvmTranscript style.
// =============================================================================

pub struct KeccakBeRead<R: Read, C: CurveAffine, E: EncodedChallenge<C>> {
    state: Vec<u8>,
    reader: R,
    _ph: PhantomData<(C, E)>,
}

impl<R, C> TranscriptReadBuffer<R, C, Challenge255<C>> for KeccakBeRead<R, C, Challenge255<C>>
where
    R: Read,
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]> + FromUniformBytes<64>,
    C::Base:   PrimeField<Repr = [u8; 32]>,
{
    fn init(reader: R) -> Self {
        Self { state: Vec::new(), reader, _ph: PhantomData }
    }
}

impl<R, C> Transcript<C, Challenge255<C>> for KeccakBeRead<R, C, Challenge255<C>>
where
    R: Read,
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]> + FromUniformBytes<64>,
    C::Base:   PrimeField<Repr = [u8; 32]>,
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        let mut input = self.state.clone();
        if input.len() == 32 { input.push(0x01); }
        let hash: [u8; 32] = Keccak256::digest(&input).into();
        self.state.clear();
        self.state.extend_from_slice(&hash);
        let mut le_padded = [0u8; 64];
        for (i, b) in hash.iter().rev().enumerate() {
            le_padded[i] = *b;
        }
        Challenge255::<C>::new(&le_padded)
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        let coords = Option::<Coordinates<C>>::from(point.coordinates()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "transcript: identity point")
        })?;
        let mut x = coords.x().to_repr();
        let mut y = coords.y().to_repr();
        x.as_mut().reverse();
        y.as_mut().reverse();
        self.state.extend_from_slice(x.as_ref());
        self.state.extend_from_slice(y.as_ref());
        Ok(())
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        let mut data = scalar.to_repr();
        data.as_mut().reverse();
        self.state.extend_from_slice(data.as_ref());
        Ok(())
    }
}

impl<R, C> TranscriptRead<C, Challenge255<C>> for KeccakBeRead<R, C, Challenge255<C>>
where
    R: Read,
    C: CurveAffine,
    C::Scalar: PrimeField<Repr = [u8; 32]> + FromUniformBytes<64>,
    C::Base:   PrimeField<Repr = [u8; 32]>,
{
    fn read_point(&mut self) -> io::Result<C> {
        // BE on the wire: read 32-byte x BE, 32-byte y BE → reverse → from_repr.
        let mut x_be = [0u8; 32]; self.reader.read_exact(&mut x_be)?;
        let mut y_be = [0u8; 32]; self.reader.read_exact(&mut y_be)?;
        let mut x_le = x_be; x_le.reverse();
        let mut y_le = y_be; y_le.reverse();
        let x: C::Base = Option::from(C::Base::from_repr(x_le))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid Fq x"))?;
        let y: C::Base = Option::from(C::Base::from_repr(y_le))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid Fq y"))?;
        let p = Option::<C>::from(C::from_xy(x, y))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "point not on curve"))?;
        // Absorb into state in the same BE order it appears on the wire.
        self.state.extend_from_slice(&x_be);
        self.state.extend_from_slice(&y_be);
        Ok(p)
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        let mut be = [0u8; 32]; self.reader.read_exact(&mut be)?;
        let mut le = be; le.reverse();
        let s: C::Scalar = Option::from(C::Scalar::from_repr(le))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "invalid Fr"))?;
        self.state.extend_from_slice(&be);
        Ok(s)
    }
}
