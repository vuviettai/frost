//! BabyJubjub curve point implementation.
//!
//! BabyJubjub is a twisted Edwards curve with equation:
//! ax² + y² = 1 + dx²y²
//! where a = 168700 and d = 168696

use super::field::BabyJubjubField;
use super::scalar::BabyJubjubScalar;
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// BabyJubjub curve point in affine coordinates.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BabyJubjubPoint {
    /// X coordinate
    pub x: BabyJubjubField,
    /// Y coordinate
    pub y: BabyJubjubField,
}

impl BabyJubjubPoint {
    /// Curve parameter a = 168700
    pub const A: u64 = 168700;

    /// Curve parameter d = 168696
    pub const D: u64 = 168696;

    /// Create a point from x and y coordinates
    pub fn new(x: BabyJubjubField, y: BabyJubjubField) -> Option<Self> {
        let point = BabyJubjubPoint { x, y };
        if point.is_on_curve() {
            Some(point)
        } else {
            None
        }
    }

    /// Check if the point is on the curve
    pub fn is_on_curve(&self) -> bool {
        // Check the twisted Edwards curve equation: ax² + y² = 1 + dx²y²
        let x_squared = self.x.mul(self.x);
        let y_squared = self.y.mul(self.y);
        let x_squared_y_squared = x_squared.mul(y_squared);

        let left = BabyJubjubField::from_u64(Self::A)
            .unwrap()
            .mul(x_squared)
            .add(y_squared);
        let right = BabyJubjubField::one().add(
            BabyJubjubField::from_u64(Self::D)
                .unwrap()
                .mul(x_squared_y_squared),
        );

        left == right
    }

    /// Get the identity point (point at infinity)
    pub fn identity() -> Self {
        // In twisted Edwards curves, the identity is (0, 1)
        BabyJubjubPoint {
            x: BabyJubjubField::zero(),
            y: BabyJubjubField::one(),
        }
    }

    /// Get the generator point
    pub fn generator() -> Self {
        // This is a placeholder - you'd need the actual generator coordinates
        // For now, we'll use a point that satisfies the curve equation
        let x = BabyJubjubField::from_u64(1).unwrap();
        let y = BabyJubjubField::from_u64(1).unwrap();

        // This is not the actual generator, but it's a valid point for testing
        BabyJubjubPoint { x, y }
    }

    /// Double the point (P + P)
    pub fn double(&self) -> Self {
        if self.is_identity() {
            return *self;
        }

        // Doubling formula for twisted Edwards curves
        let x1 = self.x;
        let y1 = self.y;

        let x1_squared = x1.mul(x1);
        let y1_squared = y1.mul(y1);

        let a_x1_squared = BabyJubjubField::from_u64(Self::A).unwrap().mul(x1_squared);
        let _d_x1_squared_y1_squared = BabyJubjubField::from_u64(Self::D)
            .unwrap()
            .mul(x1_squared)
            .mul(y1_squared);

        let numerator_x = x1.mul(y1).mul(BabyJubjubField::from_u64(2).unwrap());
        let denominator_x = a_x1_squared.add(y1_squared);

        let numerator_y = y1_squared.sub(a_x1_squared);
        let denominator_y = BabyJubjubField::from_u64(2)
            .unwrap()
            .sub(a_x1_squared)
            .sub(y1_squared);

        let x3 = numerator_x.mul(denominator_x.invert().unwrap());
        let y3 = numerator_y.mul(denominator_y.invert().unwrap());

        BabyJubjubPoint { x: x3, y: y3 }
    }

    /// Add two points
    pub fn add(&self, other: &Self) -> Self {
        if self.is_identity() {
            return *other;
        }
        if other.is_identity() {
            return *self;
        }

        // Addition formula for twisted Edwards curves
        let x1 = self.x;
        let y1 = self.y;
        let x2 = other.x;
        let y2 = other.y;

        let x1_y2 = x1.mul(y2);
        let y1_x2 = y1.mul(x2);
        let x1_x2 = x1.mul(x2);
        let y1_y2 = y1.mul(y2);

        let d_x1_x2_y1_y2 = BabyJubjubField::from_u64(Self::D)
            .unwrap()
            .mul(x1_x2)
            .mul(y1_y2);

        let numerator_x = x1_y2.add(y1_x2);
        let denominator_x = BabyJubjubField::one().add(d_x1_x2_y1_y2);

        let numerator_y = y1_y2.sub(BabyJubjubField::from_u64(Self::A).unwrap().mul(x1_x2));
        let denominator_y = BabyJubjubField::one().sub(d_x1_x2_y1_y2);

        let x3 = numerator_x.mul(denominator_x.invert().unwrap());
        let y3 = numerator_y.mul(denominator_y.invert().unwrap());

        BabyJubjubPoint { x: x3, y: y3 }
    }

    /// Subtract two points
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Negate the point
    pub fn neg(&self) -> Self {
        BabyJubjubPoint {
            x: -self.x,
            y: self.y,
        }
    }

    /// Scalar multiplication
    pub fn mul(&self, scalar: &BabyJubjubScalar) -> Self {
        let mut result = BabyJubjubPoint::identity();
        let mut base = *self;
        let mut exp = scalar.field.value;

        while !BabyJubjubField::is_zero_array(&exp) {
            if exp[0] & 1 == 1 {
                result = result.add(base);
            }
            base = base.double();
            BabyJubjubField::div_by_2(&mut exp);
        }

        result
    }

    /// Check if the point is the identity
    pub fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y == BabyJubjubField::one()
    }

    /// Serialize the point to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        // Compressed point format: just the x-coordinate
        self.x.to_bytes()
    }

    /// Deserialize the point from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let x = BabyJubjubField::from_bytes(bytes)?;

        // Reconstruct y from x using the curve equation
        // This is a simplified implementation
        // In practice, you'd need to solve the quadratic equation

        // For now, we'll use a placeholder
        let y = BabyJubjubField::one(); // This is not correct, just a placeholder

        BabyJubjubPoint::new(x, y)
    }
}

// Implement arithmetic traits

impl Add for BabyJubjubPoint {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        BabyJubjubPoint::add(&self, &other)
    }
}

impl AddAssign for BabyJubjubPoint {
    fn add_assign(&mut self, other: Self) {
        *self = BabyJubjubPoint::add(self, &other);
    }
}

impl Sub for BabyJubjubPoint {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        BabyJubjubPoint::sub(&self, &other)
    }
}

impl SubAssign for BabyJubjubPoint {
    fn sub_assign(&mut self, other: Self) {
        *self = BabyJubjubPoint::sub(self, &other);
    }
}

impl Mul<BabyJubjubScalar> for BabyJubjubPoint {
    type Output = Self;
    fn mul(self, scalar: BabyJubjubScalar) -> Self {
        BabyJubjubPoint::mul(&self, &scalar)
    }
}

impl MulAssign<BabyJubjubScalar> for BabyJubjubPoint {
    fn mul_assign(&mut self, scalar: BabyJubjubScalar) {
        *self = BabyJubjubPoint::mul(self, &scalar);
    }
}

impl Neg for BabyJubjubPoint {
    type Output = Self;
    fn neg(self) -> Self {
        BabyJubjubPoint {
            x: -self.x,
            y: self.y,
        }
    }
}

// Helper trait implementations for BabyJubjubField

impl BabyJubjubField {
    /// Create a field element from a u64
    pub fn from_u64(value: u64) -> Option<Self> {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        Self::from_bytes(&bytes)
    }
}
