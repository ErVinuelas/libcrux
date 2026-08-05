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
pub use p384_64::{
    fiat_p384_montgomery_domain_field_element as Fp,
    fiat_p384_non_montgomery_domain_field_element as FpRaw,
};

mod safegcd;
mod safegcd_p384;

#[inline]
pub fn fp_add(out: &mut Fp, x: &Fp, y: &Fp) {
    fiat_p384_add(out, x, y)
}
#[inline]
pub fn fp_sub(out: &mut Fp, x: &Fp, y: &Fp) {
    fiat_p384_sub(out, x, y)
}
#[inline]
pub fn fp_mul(out: &mut Fp, x: &Fp, y: &Fp) {
    fiat_p384_mul(out, x, y)
}
#[inline]
pub fn fp_square(out: &mut Fp, x: &Fp) {
    fiat_p384_square(out, x)
}
#[inline]
pub fn fp_opp(out: &mut Fp, x: &Fp) {
    fiat_p384_opp(out, x)
}
#[inline]
pub fn fp_to_bytes(out: &mut [u8; 384 / 8 + (384 % 8 > 0) as usize], x: &Fp) {
    fiat_p384_to_bytes(out, &x.0)
}
#[inline]
pub fn fp_from_bytes(out: &mut FpRaw, bs: &[u8; 384 / 8 + (384 % 8 > 0) as usize]) {
    fiat_p384_from_bytes(&mut out.0, bs)
}
#[inline]
pub fn fp_to_montgomery(out: &mut Fp, x: &FpRaw) {
    fiat_p384_to_montgomery(out, x)
}
#[inline]
pub fn fp_from_montgomery(out: &mut FpRaw, x: &Fp) {
    fiat_p384_from_montgomery(out, x)
}

/// Constant-time modular inverse via the Bernstein–Yang divstep port.
/// Input/output are in Montgomery form.  Convert out → invert → convert in.
pub fn fp_inv(out: &mut Fp, x: &Fp) {
    let mut raw_in = FpRaw([0u64; 6]);
    fp_from_montgomery(&mut raw_in, x);
    let mut raw_inv = [0u64; 6];
    safegcd_p384::p384_invert_divstep_sat(&mut raw_inv, &raw_in.0);
    fp_to_montgomery(out, &FpRaw(raw_inv));
}

#[cfg(test)]
mod kat;
