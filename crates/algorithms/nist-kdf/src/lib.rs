#![no_std]
#![doc = include_str!("../README.md")]
use core::fmt::{Debug, Display};

pub mod feedback;
pub mod two_step;

#[derive(Debug)]
pub struct KdfError;

impl Display for KdfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NIST KDF Error")
    }
}

impl core::error::Error for KdfError {}
