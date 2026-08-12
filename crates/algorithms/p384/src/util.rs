//! # Utility functions

/// Big-endian byte-array comparison: is `a < b`? Used both to reject
/// non-canonical (unreduced) field element encodings and to rejection-sample
/// private keys against the curve order.
///
/// This is not fully constant-time. In particular, it exits early if
/// `a > b`. This is safe, since when the outcome is `false` the input
/// will be rejected and thus not considered secret.
#[inline]
pub(crate) fn be_bytes_lt(a: &[u8; 48], b: &[u8; 48]) -> bool {
    let mut check = 0u8;
    for i in 0..48 {
        if a[i] > b[i] {
            // For every previous i, we had a[i] <= b[i], so if any of them disagreed,
            // a[i] was smaller than b[i], thus a < b.
            return check != 0;
        }
        check |= a[i] ^ b[i];
    }

    // For every i, we had a[i] <= b[i], so if any of them disagreed,
    // a[i] was smaller than b[i], thus a < b.
    check != 0
}

#[inline]
pub(crate) fn be_bytes_nonzero(x: &[u8; 48]) -> bool {
    let mut check = 0u8;
    for byte in x {
        check |= *byte;
    }
    check != 0
}
