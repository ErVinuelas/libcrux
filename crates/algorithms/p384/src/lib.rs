/// Base Field Arithmetic for P-384
pub(crate) mod field;

/// Elliptic Curve operations in P-384
mod curve;

/// ECDH over P-384
pub mod ecdh;

/// ECDSA over P-384
pub mod ecdsa;

pub use curve::ProjectivePoint as PublicKey;

#[derive(Copy, Clone, Debug)]
pub enum Error {
    /// Error during deserialization of an uncompressed curve point
    InvalidUncompressed,
    /// When attempting to convert the point at infinity to affine coordinates
    PointAtInfinity,
}
