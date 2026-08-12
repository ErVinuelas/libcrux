use crate::{
    curve::{affine::AffinePoint, ProjectivePoint},
    EcdhError as Error,
};

pub(crate) mod private;

use private::PrivateKey;

/// A P-384 shared secret.
pub struct SharedSecret(
    /// This point can never be the point at infinity.
    pub(crate) ProjectivePoint,
);

impl SharedSecret {
    /// Convert the shared secret to bytes, if possible.
    ///
    /// If the shared secret represents the point at infinity, return `None`.
    pub fn to_bytes(&self) -> [u8; 48] {
        let affine = self
            .0
            .to_affine()
            .expect("shared secret can never be point at infinity");

        affine.x.to_be_bytes()
    }
}

/// An ECDH public key.
pub struct PublicKey(
    /// This point can never be the point at infinity.
    ProjectivePoint,
);

impl PublicKey {
    /// Derives an ECDH shared secret from the public key and a scalar.
    pub fn ecdh(&self, private_key: &PrivateKey) -> SharedSecret {
        SharedSecret(
            // This can never be the point at inifinity, since self.0
            // is not the point at infinity and the private key is
            // non-zero.
            self.0.scalar_mul(&private_key.0),
        )
    }
    /// Read the SEC1 compressed encoding of a public key from the input
    /// buffer.
    ///
    /// Returns an error if the buffer does not contain a valid encoding of a
    /// point on P-384.
    pub fn from_uncompressed(uncompressed_bytes: &[u8]) -> Result<Self, Error> {
        let p_affine = AffinePoint::from_uncompressed(uncompressed_bytes)
            .map_err(|_| Error::InvalidPublicKey)?;

        if p_affine.validate() {
            // This can never be the point at infinity, since there is
            // no affine encoding for the point at infinity.
            Ok(Self(p_affine.into()))
        } else {
            Err(Error::InvalidPublicKey)
        }
    }

    /// Read the SEC1 compressed encoding of a public key from the input
    /// buffer.
    ///
    /// Returns an error if the buffer does not contain a valid encoding of a
    /// point on P-384.
    pub fn from_compressed(compressed_bytes: &[u8]) -> Result<Self, Error> {
        // This can never be the point at infinity, since there is
        // no affine encoding for the point at infinity.
        AffinePoint::from_compressed(compressed_bytes)
            .map(|p| Self(p.into()))
            .map_err(|_| Error::InvalidPublicKey)
    }

    /// Write the SEC1 uncompressed encoding of the public key into the
    /// provided buffer `out`.
    pub fn to_uncompressed(self, out: &mut [u8; 97]) {
        let affine = self
            .0
            .to_affine()
            .expect("public key can never be point at infinity");

        affine.to_uncompressed(out);
    }

    /// Write the SEC1 compressed encoding of the public key into the provided
    /// buffer `out`.
    pub fn to_compressed(self, out: &mut [u8; 49]) {
        let affine = self
            .0
            .to_affine()
            .expect("public key can never be point at infinity");

        affine.to_compressed(out);
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    /// Attempt decoding if input length matches either compressed or
    /// uncompressed encoding lengths.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            49 => Self::from_compressed(value),
            97 => Self::from_uncompressed(value),
            _ => Err(Error::InvalidPublicKey),
        }
    }
}

impl From<&PrivateKey> for PublicKey {
    /// For a given private key `x`, the corresponding public key is
    /// `xG`, where `G` is the group generator.
    fn from(value: &PrivateKey) -> Self {
        // This can never be the point at infinity, since the
        // generator is not the point at infinity, and the private
        // key is non-zero.
        Self(ProjectivePoint::generator().scalar_mul(&value.0))
    }
}
