/// Big-endian byte-array comparison: is `a < b`? Used both to reject
/// non-canonical (unreduced) field element encodings and to rejection-sample
/// private keys against the curve order.
/// XXX: Need constant-time?
#[inline]
pub(crate) fn be_bytes_lt(a: &[u8; 48], b: &[u8; 48]) -> bool {
    for i in 0..48 {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}
