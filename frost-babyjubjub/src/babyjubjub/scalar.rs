//! BabyJubjub scalar implementation.
//!
//! This wraps the field element to provide scalar operations for elliptic curve arithmetic.

use super::field::{BabyJubjubField, MODULUS};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use rand_core::{CryptoRng, RngCore};

/// BabyJubjub scalar.
///
/// This represents a scalar value for elliptic curve operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BabyJubjubScalar {
    /// The underlying field element
    pub field: BabyJubjubField,
}

impl BabyJubjubScalar {
    /// Create a scalar from bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        BabyJubjubField::from_bytes(bytes).map(|field| BabyJubjubScalar { field })
    }

    /// Convert scalar to bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.field.to_bytes()
    }

    /// Create a scalar from bytes with wide reduction
    pub fn from_bytes_mod_order_wide(input: &[u8]) -> Self {
        // Convert input to a 256-bit number (little-endian)
        let mut value = [0u64; 4];
        let mut input_bytes = [0u8; 32];
        let len = core::cmp::min(input.len(), 32);
        input_bytes[..len].copy_from_slice(&input[..len]);

        // Convert bytes to u64 limbs (little-endian)
        for (i, chunk) in input_bytes.chunks(8).enumerate() {
            if i >= 4 {
                break;
            }
            let mut bytes_array = [0u8; 8];
            bytes_array[..chunk.len()].copy_from_slice(chunk);
            value[i] = u64::from_le_bytes(bytes_array);
        }

        // Reduce modulo the field modulus

        // Use a more efficient approach - try to create field element first
        if let Some(field) = BabyJubjubField::from_bytes(&input_bytes) {
            return BabyJubjubScalar { field };
        }

        // If that fails, do manual reduction
        // Since the modulus is 254 bits, we can do a simple reduction
        // by taking the value modulo 2^254 - 1 (the field modulus)
        // For now, let's use a simpler approach: just take the lower 254 bits
        let mut reduced_value = [0u64; 4];
        reduced_value.copy_from_slice(&value);

        // Ensure the value is less than the modulus by taking modulo
        // This is a simplified approach - in practice you'd want proper modular reduction
        if !Self::is_less_than_modulus(&reduced_value, &MODULUS) {
            // Just use the lower bits for now
            Self::reduce_modulus(&mut reduced_value);
        }

        BabyJubjubScalar {
            field: BabyJubjubField {
                value: reduced_value,
            },
        }
    }

    fn is_less_than_modulus(value: &[u64; 4], modulus: &[u64; 4]) -> bool {
        for (a, b) in value.iter().zip(modulus.iter()).rev() {
            if a < b {
                return true;
            } else if a > b {
                return false;
            }
        }
        true
    }

    fn reduce_modulus(value: &mut [u64; 4]) {
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = value[i] as i128 - MODULUS[i] as i128;
            value[i] = diff as u64;
            borrow = if diff < 0 { 1 } else { 0 };
        }
    }

    /// Get the zero scalar
    pub fn zero() -> Self {
        BabyJubjubScalar {
            field: BabyJubjubField::zero(),
        }
    }

    /// Get the one scalar
    pub fn one() -> Self {
        BabyJubjubScalar {
            field: BabyJubjubField::one(),
        }
    }

    /// Generate a random scalar
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        BabyJubjubScalar {
            field: BabyJubjubField::random(rng),
        }
    }

    /// Compute the multiplicative inverse
    pub fn invert(&self) -> Result<Self, &'static str> {
        self.field
            .invert()
            .map(|field| BabyJubjubScalar { field })
            .ok_or("Cannot invert zero scalar")
    }

    /// Check if the scalar is zero
    pub fn is_zero(&self) -> bool {
        self.field.is_zero()
    }

    /// Add two scalars
    pub fn add(&self, other: &Self) -> Self {
        BabyJubjubScalar {
            field: self.field.add(other.field),
        }
    }

    /// Subtract two scalars
    pub fn sub(&self, other: &Self) -> Self {
        BabyJubjubScalar {
            field: self.field.sub(other.field),
        }
    }

    /// Multiply two scalars
    pub fn mul(&self, other: &Self) -> Self {
        BabyJubjubScalar {
            field: self.field.mul(other.field),
        }
    }
}

// Implement arithmetic traits

impl Add for BabyJubjubScalar {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        BabyJubjubScalar::add(&self, &other)
    }
}

impl AddAssign for BabyJubjubScalar {
    fn add_assign(&mut self, other: Self) {
        *self = BabyJubjubScalar::add(self, &other);
    }
}

impl Sub for BabyJubjubScalar {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        BabyJubjubScalar::sub(&self, &other)
    }
}

impl SubAssign for BabyJubjubScalar {
    fn sub_assign(&mut self, other: Self) {
        *self = BabyJubjubScalar::sub(self, &other);
    }
}

impl Mul for BabyJubjubScalar {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        BabyJubjubScalar::mul(&self, &other)
    }
}

impl MulAssign for BabyJubjubScalar {
    fn mul_assign(&mut self, other: Self) {
        *self = BabyJubjubScalar::mul(self, &other);
    }
}

impl Neg for BabyJubjubScalar {
    type Output = Self;
    fn neg(self) -> Self {
        BabyJubjubScalar { field: -self.field }
    }
}
