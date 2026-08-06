// XXX: Do not derive Debug, Default, PartialEq on scalars.

/// Base Field Arithmetic for P-384
pub(crate) mod field;

/// Elliptic Curve operations in P-384
mod curve;

mod constants;

/// ECDH over P-384
pub mod ecdh;

/// ECDSA over P-384
pub mod ecdsa;

mod util;

pub use curve::ProjectivePoint as PublicKey;

use crate::curve::{AffinePoint, SecretKey};

#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Error when deserializing a secret key
    InvalidSecretKey,
    /// Error when deserializing a field element
    InvalidFieldElement,
    /// Error during deserialization of an uncompressed curve point
    InvalidUncompressed,
    /// When attempting to convert the point at infinity to affine coordinates
    PointAtInfinity,
}

pub fn derive_ecdh(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<[u8; 48], Error> {
    let sk_bytes: &[u8; 48] = sk_bytes.try_into().map_err(|_| Error::InvalidSecretKey)?;

    // XXX: Match on length for other encodings
    let pk = PublicKey::from_uncompressed(pk_bytes)?;

    let ecdh = pk.scalar_mul(sk_bytes)?;
    let ecdh = AffinePoint::try_from(ecdh)?;

    Ok(ecdh.x.to_be_bytes())
}
