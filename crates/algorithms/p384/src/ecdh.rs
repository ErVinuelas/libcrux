use crate::curve::PublicKey;

/// A P-384 shared secret.
pub struct SharedSecret(pub(crate) PublicKey);

impl SharedSecret {
    /// Convert the shared secret to bytes, if possible.
    ///
    /// If the shared secret represents the point at infinity, return `None`.
    pub fn to_bytes(&self) -> Option<[u8; 48]> {
        let affine = self.0.to_affine()?;

        Some(affine.x.to_be_bytes())
    }
}
