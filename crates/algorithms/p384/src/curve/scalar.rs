#[cfg(feature = "rand")]
use rand::TryCryptoRng;

#[cfg(feature = "rand")]
/// # P-384 Private Keys
///
/// Private keys are field elements in Fp which are bounded by the
/// curve order of P-384.
use crate::Error;
use crate::{constants::NIST_P384_CURVE_ORDER_BE_BYTES, util::be_bytes_lt};

/// A P-384 private key.
pub struct PrivateKey(pub(crate) [u8; 48]);

#[cfg(feature = "rand")]
/// How many times to retry sampling a valid scalar during key generation.
const SCALAR_REJ_SAMPLING_BOUND: usize = 5;

impl PrivateKey {
    #[cfg(feature = "rand")]
    /// Generate a fresh private key.
    ///
    /// Performs rejection sampling internally, and may return an error if
    /// rejection sampling does not succeed in a particular number of
    /// attempts, indicating a major failure of randomness generation.
    pub fn generate(rng: &mut impl TryCryptoRng) -> Result<Self, Error> {
        let mut bytes = [0u8; 48];
        let mut attempts = 0;
        rng.try_fill_bytes(&mut bytes)
            .map_err(|_| Error::RandomnessError)?;

        while attempts < SCALAR_REJ_SAMPLING_BOUND {
            let res = Self::try_from(bytes.as_slice());

            if res.is_ok() {
                return res;
            } else {
                attempts += 1
            }
        }
        Err(Error::RandomnessError)
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = crate::Error;

    /// A valid SEC1 encoding of a P-384 private key is a 48 byte
    /// big-endian integer that is less than the P-384 curve order.
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let value: [u8; 48] = value
            .try_into()
            .map_err(|_| Self::Error::InvalidPrivateKey)?;
        if be_bytes_lt(&value, &NIST_P384_CURVE_ORDER_BE_BYTES) {
            Ok(Self(value))
        } else {
            Err(Self::Error::InvalidPrivateKey)
        }
    }
}
