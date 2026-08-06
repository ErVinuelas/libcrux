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
