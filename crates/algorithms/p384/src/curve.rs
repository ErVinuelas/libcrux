use crate::{
    constants::{
        fpraw_from_be_bytes, FP_ONE, NIST_P384_A, NIST_P384_B, NIST_P384_CURVE_ORDER_BE_BYTES,
        NIST_P384_GX, NIST_P384_GX_BE_BYTES, NIST_P384_GY, NIST_P384_GY_BE_BYTES,
    },
    field::{
        fiat_p384_set_one, fp_add, fp_from_bytes, fp_from_montgomery, fp_inv, fp_mul, fp_nonzero,
        fp_square, fp_sub, fp_to_montgomery, Fp, FpRaw,
    },
    Error,
};

/// A point on P-384 in affine representation.
#[derive(Default)]
struct AffinePoint {
    x: FpRaw,
    y: FpRaw,
}

/// A point on P-384 in projective representation.
pub struct ProjectivePoint {
    x: Fp,
    y: Fp,
    z: Fp,
}

pub fn compressed_to_raw(compressed_bytes: &[u8], out: &mut [u8; 96]) -> bool {
    todo!("Point decompression is not implemented yet.")
}

impl AffinePoint {
    /// Decode an uncompressed encoding of an affine point.
    ///
    /// This function does not validate the curve point.
    fn from_uncompressed(uncompressed_bytes: &[u8]) -> Result<Self, Error> {
        if uncompressed_bytes.len() != 97 || uncompressed_bytes[0] != 0x04 {
            return Err(Error::InvalidUncompressed);
        }

        let x_bytes = &uncompressed_bytes[1..49];
        let y_bytes = &uncompressed_bytes[49..];

        let x_raw = FpRaw::from_be_bytes(x_bytes.try_into().expect("x_bytes is 48 bytes long"));
        let y_raw = FpRaw::from_be_bytes(y_bytes.try_into().expect("y_bytes is 48 bytes long"));

        Ok(AffinePoint { x: x_raw, y: y_raw })
    }

    /// Validate the curve equation.
    fn validate(&self) -> bool {
        let x = Fp::from_raw(&self.x);
        let y = Fp::from_raw(&self.y);

        let y_squared = y.square();

        let x_cubed = x.mul(&x.square());
        let ax = x.mul(&NIST_P384_A);
        let rhs = x_cubed.add(&ax).add(&NIST_P384_B);

        !fp_nonzero(&y_squared.sub(&rhs))
    }
}

impl ProjectivePoint {
    /// Complete point addition for prime order short Weierstrass
    /// curves with a = -3 from Renes, Costello, and Batina.
    fn add(&self, other: &Self) -> Self {
        let ProjectivePoint {
            x: x1,
            y: y1,
            z: z1,
        } = &self;

        let ProjectivePoint {
            x: x2,
            y: y2,
            z: z2,
        } = other;

        let mut t0 = x1.mul(x2); // 1.
        let mut t1 = y1.mul(y2); // 2.
        let mut t2 = z1.mul(z2); // 3.
        let mut t3 = x1.add(y1); // 4.
        let mut t4 = x2.add(y2); // 5.
        t3.mul_assign(&t4); // 6.
        t4 = t0.add(&t1); // 7.
        t3.sub_assign(&t4); // 8.
        t4 = y1.add(z1); // 9.
        let mut x3 = y2.add(z2); // 10.
        t4.mul_assign(&x3); // 11.
        x3 = t1.add(&t2); // 12.
        t4.sub_assign(&x3); // 13.
        x3 = x1.add(z1); // 14.
        let mut y3 = x2.add(z2); // 15.
        x3.mul_assign(&y3); // 16.
        y3 = t0.add(&t2); // 17.
        y3 = x3.sub(&y3); // 18.
        let mut z3 = t2.mul(&NIST_P384_B); // 19.
        x3 = y3.sub(&z3); // 20.
        z3 = x3.double(); // 21.
        x3.add_assign(&z3); // 22.
        z3 = t1.sub(&x3); // 23.
        x3.add_assign(&t1); // 24.
        y3.mul_assign(&NIST_P384_B); // 25.
        t1 = t2.double(); // 26.
        t2.add_assign(&t1); // 27.
        y3.sub_assign(&t2); // 28.
        y3.sub_assign(&t0); // 29.
        t1 = y3.double(); // 30.
        y3.add_assign(&t1); // 31.
        t1 = t0.double(); // 32.
        t0.add_assign(&t1); // 33.
        t0.sub_assign(&t2); // 34.
        t1 = t4.mul(&y3); // 35.
        t2 = t0.mul(&y3); // 36.
        y3 = x3.mul(&z3); // 37.
        y3.add_assign(&t2); // 38.
        x3.mul_assign(&t3); // 39.
        x3.sub_assign(&t1); // 40.
        z3.mul_assign(&t4); // 41.
        t1 = t3.mul(&t0); // 42.
        z3.add_assign(&t1); // 43.

        ProjectivePoint {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Convert a point in uncompressed encoding into a projective curve point.
    ///
    /// The uncompressed encoding of a curve point P is a 97-byte slice starting with
    /// byte `0x04`, followed by 48-byte encodings of affine point
    /// coordinates x_P and y_P:
    ///
    ///   P_uncompressed = `0x04` || X || Y
    ///
    /// where X = FE2OS(x_P) and Y = FE2OS(y_P) are the encodings of curve
    /// coordinates as ocetet strings. The raw encoding is a 96-byte
    /// array containing the encodings of affine point coordinates X and
    /// Y:
    ///
    ///   P_raw = X || Y
    ///
    /// If this function returns `true` the content of `out` will be the
    /// raw encoding of a valid curve point that was encoded in
    /// `uncompressed_bytes`, in particular, the function validates that
    ///
    ///   y_P^2 = x_P^3 + ax_P + b
    ///
    /// where a = -3 and b is the curve parameter for NIST P-384 as
    /// defined in FIPS 186-4.
    pub fn from_uncompressed(uncompressed_bytes: &[u8]) -> Result<Self, Error> {
        let p_affine = AffinePoint::from_uncompressed(uncompressed_bytes)?;

        if p_affine.validate() {
            Ok(p_affine.into())
        } else {
            Err(Error::InvalidUncompressed)
        }
    }

    fn is_point_at_infinity(&self) -> bool {
        let mut y_inf = Fp::default();
        fiat_p384_set_one(&mut y_inf);

        let mut diff_y = Fp::default();

        fp_sub(&mut diff_y, &self.y, &y_inf);

        !fp_nonzero(&self.x) | !fp_nonzero(&self.z) | fp_nonzero(&diff_y)
    }
}

impl From<AffinePoint> for ProjectivePoint {
    fn from(value: AffinePoint) -> Self {
        let mut x = Fp::default();
        fp_to_montgomery(&mut x, &value.x);

        let mut y = Fp::default();
        fp_to_montgomery(&mut y, &value.y);

        let mut z = Fp::default();
        fiat_p384_set_one(&mut z);

        ProjectivePoint { x, y, z }
    }
}

impl TryFrom<ProjectivePoint> for AffinePoint {
    type Error = Error;

    fn try_from(value: ProjectivePoint) -> Result<Self, Self::Error> {
        if value.is_point_at_infinity() {
            return Err(Error::PointAtInfinity);
        }

        let mut z_inv = Fp::default();
        fp_inv(&mut z_inv, &value.z);

        let mut x = Fp::default();
        fp_mul(&mut x, &value.x, &z_inv);

        let mut y = Fp::default();
        fp_mul(&mut y, &value.y, &z_inv);

        let mut affine_point = AffinePoint::default();
        fp_from_montgomery(&mut affine_point.x, &x);
        fp_from_montgomery(&mut affine_point.y, &y);

        Ok(affine_point)
    }
}
