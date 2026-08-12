//! # Affine Coordinate Representation
//!
//! We don't use affine coordinates for curve operations, only as a
//! helper during serialization and deserialization.

use core::ops::Neg;

use crate::{constants::FP_ZERO, field::Fp, InternalError};

/// A point on P-384 in affine representation.
pub(crate) struct AffinePoint {
    pub(crate) x: Fp,
    pub(crate) y: Fp,
}

impl AffinePoint {
    /// Read a SEC1 uncompressed encoding of an affine point.
    ///
    /// This function validates the correctness of the encoding, but *does
    /// not* validate the curve point itself. For checking curve membership,
    /// use `AffinePoint::validate`.
    ///
    /// The uncompressed encoding of a curve point P is a 97-byte slice starting with
    /// byte `0x04`, followed by 48-byte encodings of affine point
    /// coordinates x_P and y_P:
    ///
    ///   P_uncompressed = `0x04` || X || Y
    ///
    /// where X = FE2OS(x_P) and Y = FE2OS(y_P) are the encodings of curve
    /// coordinates as octet strings.
    pub(crate) fn from_uncompressed(uncompressed_bytes: &[u8]) -> Result<Self, InternalError> {
        if uncompressed_bytes.len() != 97 || uncompressed_bytes[0] != 0x04 {
            return Err(InternalError::Uncompressed);
        }

        let x_bytes = &uncompressed_bytes[1..49];
        let y_bytes = &uncompressed_bytes[49..];

        let x = Fp::from_be_bytes(x_bytes.try_into().expect("x_bytes is 48 bytes long"))
            .map_err(|_| InternalError::Uncompressed)?;
        let y = Fp::from_be_bytes(y_bytes.try_into().expect("y_bytes is 48 bytes long"))
            .map_err(|_| InternalError::Uncompressed)?;

        Ok(AffinePoint { x, y })
    }

    /// Read the SEC1 compressed encoding of an affine point from the input
    /// buffer.
    ///
    /// Returns an error if the buffer does not contain a valid encoding of a
    /// point on P-384.
    ///
    /// A valid encoding has the form `y_P || FE2OS(X)`, where `y_P` is one byte
    /// with value either `0x02` or `0x03` and `FE2OS(X)` is the 48-byte
    /// encoding of the X coordinate of the candidate point.
    ///
    /// Curve membership is tested by computing the right-hand side of the
    /// short Weierstrass equation Y' = X^3 + aX + b. The point is on the
    /// curve, if Y' is a square. If Y' is non-zero, which of two possible
    /// points was encoded is determined from `y_P`.
    pub fn from_compressed(compressed_bytes: &[u8]) -> Result<Self, InternalError> {
        if compressed_bytes.len() != 49 {
            return Err(InternalError::Compressed);
        }
        if !(compressed_bytes[0] == 0x02 || compressed_bytes[0] == 0x03) {
            return Err(InternalError::Compressed);
        }

        let expect_odd = compressed_bytes[0] == 0x03;

        let x = Fp::from_be_bytes(
            &compressed_bytes[1..]
                .try_into()
                .expect("remainder of `compressed_bytes` is 48 bytes long"),
        )
        .map_err(|_| InternalError::Compressed)?;

        let weierstrass_lhs = x.weierstrass_rhs();

        if weierstrass_lhs.is_zero() {
            // XXX: In this case, do we require a specific value for `expect_odd`?
            Ok(AffinePoint { x, y: FP_ZERO })
        } else if let Some(y) = weierstrass_lhs.sqrt() {
            if y.is_odd() == expect_odd {
                Ok(AffinePoint { x, y })
            } else {
                Ok(AffinePoint { x, y: y.neg() })
            }
        } else {
            Err(InternalError::Compressed)
        }
    }

    /// Write the SEC1 uncompressed encoding of the affine point into the
    /// provided buffer `out`.
    pub(crate) fn to_uncompressed(&self, out: &mut [u8; 97]) {
        out[0] = 0x04;
        out[1..49].copy_from_slice(&self.x.to_be_bytes());
        out[49..].copy_from_slice(&self.y.to_be_bytes());
    }

    /// Write the SEC1 compressed encoding of the affine point into the provided
    /// buffer `out`.
    pub(crate) fn to_compressed(&self, out: &mut [u8; 49]) {
        if self.y.is_odd() {
            out[0] = 0x03;
        } else {
            out[0] = 0x02;
        }
        out[1..49].copy_from_slice(&self.x.to_be_bytes());
    }

    /// Validate the curve equation.
    ///
    /// That is, check whether Y^2 = X^3 + aX + b.
    pub(crate) fn validate(&self) -> bool {
        let y_squared = self.y.square();
        let rhs = self.x.weierstrass_rhs();

        (&y_squared - &rhs).is_zero()
    }
}
