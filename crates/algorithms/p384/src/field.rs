// This file adapted from https://github.com/AU-COBRA/AUCurves/blob/d4159c1b8a91f2f832761c72f00caa8fb59ec472/p384-safe-rust/src/lib.rs
//! p384 field arithmetic — fiat-rust leaves + Bernstein-Yang inverse.
//!
//! Field operations (add, sub, mul, square, opp, to/from Montgomery,
//! to/from bytes) come from the auto-generated, machine-checked
//! `fiat-crypto/fiat-rust/src/p384_64.rs`.  Constant-time modular
//! inversion comes from the Bernstein-Yang divstep port in
//! `safegcd-rs/src/safegcd_p384.rs` (verified against the
//! convergence certificate in
//! `src/Arithmetic/safegcd/divsteps_p384_half.v`).
//!
//! 384-bit prime, 6×u64 saturated limb representation.

#![allow(non_snake_case, non_camel_case_types)]

mod p384_64;
use p384_64::*;
pub(crate) use p384_64::{
    fiat_p384_montgomery_domain_field_element as Fp,
    fiat_p384_non_montgomery_domain_field_element as FpRaw, fiat_p384_nonzero, fiat_p384_set_one,
};

use crate::{
    constants::{fpraw_from_be_bytes, NIST_P384_P_BE_BYTES},
    util::be_bytes_lt,
    Error,
};

mod safegcd;
mod safegcd_p384;

#[inline]
/// The function fp_add adds two field elements in the Montgomery domain.
///
/// ```text
/// Preconditions:
///   0 ≤ eval arg1 < m
///   0 ≤ eval arg2 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) + eval (from_montgomery arg2)) mod m
///   0 ≤ eval out1 < m
/// ```
pub(crate) const fn fp_add(out: &mut Fp, x: &Fp, y: &Fp) {
    fiat_p384_add(out, x, y)
}

#[inline]
/// The function fp_sub subtracts two field elements in the Montgomery domain.
///
/// ```text
/// Preconditions:
///   0 ≤ eval arg1 < m
///   0 ≤ eval arg2 < m
/// Postconditions:
///   eval (from_montgomery out1) mod m = (eval (from_montgomery arg1) - eval (from_montgomery arg2)) mod m
///   0 ≤ eval out1 < m
/// ```
pub(crate) const fn fp_sub(out: &mut Fp, x: &Fp, y: &Fp) {
    fiat_p384_sub(out, x, y)
}

#[inline]
pub(crate) fn fp_mul(out: &mut Fp, x: &Fp, y: &Fp) {
    fiat_p384_mul(out, x, y)
}

#[inline]
pub(crate) fn fp_square(out: &mut Fp, x: &Fp) {
    fiat_p384_square(out, x)
}
#[inline]
pub(crate) const fn fp_opp(out: &mut Fp, x: &Fp) {
    fiat_p384_opp(out, x)
}
#[inline]
pub(crate) fn fp_to_bytes(out: &mut [u8; 384 / 8 + (384 % 8 > 0) as usize], x: &Fp) {
    fiat_p384_to_bytes(out, &x.0)
}
#[inline]
pub(crate) const fn fp_from_bytes(out: &mut FpRaw, bs: &[u8; 384 / 8 + (384 % 8 > 0) as usize]) {
    fiat_p384_from_bytes(&mut out.0, bs)
}
#[inline]
pub(crate) const fn fp_to_montgomery(out: &mut Fp, x: &FpRaw) {
    fiat_p384_to_montgomery(out, x)
}
#[inline]
pub(crate) fn fp_from_montgomery(out: &mut FpRaw, x: &Fp) {
    fiat_p384_from_montgomery(out, x)
}

#[inline]
pub(crate) fn fp_nonzero(x: &Fp) -> bool {
    let mut test = 0;
    fiat_p384_nonzero(&mut test, &x.0);
    test != 0
}

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

impl Add<&Fp> for &Fp {
    type Output = Fp;

    fn add(self, rhs: &Fp) -> Self::Output {
        let mut out = Fp::new();
        fp_add(&mut out, self, rhs);
        out
    }
}
impl Mul<&Fp> for &Fp {
    type Output = Fp;

    fn mul(self, rhs: &Fp) -> Self::Output {
        let mut out = Fp::new();
        fp_mul(&mut out, self, rhs);
        out
    }
}
impl Sub<&Fp> for &Fp {
    type Output = Fp;

    fn sub(self, rhs: &Fp) -> Self::Output {
        let mut out = Fp::new();
        fp_sub(&mut out, self, rhs);
        out
    }
}
impl Neg for &Fp {
    type Output = Fp;

    fn neg(self) -> Self::Output {
        let mut out = Fp::new();
        fp_opp(&mut out, self);
        out
    }
}
impl AddAssign for Fp {
    fn add_assign(&mut self, rhs: Self) {
        let mut tmp = Fp::new();
        fp_add(&mut tmp, &self, &rhs);
        *self = tmp;
    }
}

impl SubAssign for Fp {
    fn sub_assign(&mut self, rhs: Self) {
        let mut tmp = Fp::new();
        fp_sub(&mut tmp, &self, &rhs);
        *self = tmp;
    }
}

impl MulAssign for Fp {
    fn mul_assign(&mut self, rhs: Self) {
        let mut tmp = Fp::new();
        fp_mul(&mut tmp, &self, &rhs);
        *self = tmp;
    }
}

impl Fp {
    pub(crate) const fn new() -> Self {
        Self([0u64; 6])
    }

    #[must_use]
    pub(crate) fn from_raw(raw: &FpRaw) -> Fp {
        let mut result = Fp::default();
        fp_to_montgomery(&mut result, raw);
        result
    }
}

impl FpRaw {
    /// Create a new standard form field element.
    ///
    /// Only need this because we can't implement `Default` as `const`.
    pub(crate) const fn new() -> Self {
        Self([0u64; 6])
    }

    /// Parse a standard form field element from big-endian bytes.
    ///
    /// Returns `None` if the encoded integer is unreduced, i.e. larger than the field modulus.
    pub(crate) fn from_be_bytes(bytes: &[u8; 48]) -> Result<Self, Error> {
        if !be_bytes_lt(bytes, &NIST_P384_P_BE_BYTES) {
            return Err(Error::InvalidFieldElement);
        }
        Ok(fpraw_from_be_bytes(bytes))
    }
}

/// Constant-time modular inverse via the Bernstein–Yang divstep port.
/// Input/output are in Montgomery form.  Convert out → invert → convert in.
pub(crate) fn fp_inv(out: &mut Fp, x: &Fp) {
    let mut raw_in = FpRaw([0u64; 6]);
    fp_from_montgomery(&mut raw_in, x);
    let mut raw_inv = [0u64; 6];
    safegcd_p384::p384_invert_divstep_sat(&mut raw_inv, &raw_in.0);
    fp_to_montgomery(out, &FpRaw(raw_inv));
}

#[cfg(test)]
mod kat;
