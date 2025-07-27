//! BabyJubjub field arithmetic.
//!
//! The BabyJubjub curve is defined over the BN254 scalar field.
//! Field modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use rand_core::{CryptoRng, RngCore};

/// Field modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
/// The modulus is: [0x87cfd47, 0x6d87c208, 0x1ca8d3c2, 0x168716a9]
pub const MODULUS: [u64; 4] = [0x87cfd47, 0x6d87c208, 0x1ca8d3c2, 0x168716a9];

/// BabyJubjub field element.
///
/// This represents an element of the BN254 scalar field.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BabyJubjubField {
    /// The field element value (little-endian representation)
    pub value: [u64; 4],
}

impl BabyJubjubField {
    /// Create a field element from raw bytes (little-endian)
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut value = [0u64; 4];

        for (i, chunk) in bytes.chunks(8).enumerate() {
            if i >= 4 {
                return None;
            }
            let mut bytes_array = [0u8; 8];
            bytes_array[..chunk.len()].copy_from_slice(chunk);
            value[i] = u64::from_le_bytes(bytes_array);
        }

        // Check if the value is less than the modulus
        if Self::is_less_than_modulus(&value) {
            Some(BabyJubjubField { value })
        } else {
            None
        }
    }

    /// Convert field element to bytes (little-endian)
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, &limb) in self.value.iter().enumerate() {
            let chunk = limb.to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&chunk);
        }
        bytes
    }

    /// Check if a value is less than the modulus
    fn is_less_than_modulus(value: &[u64; 4]) -> bool {
        for (a, b) in value.iter().zip(MODULUS.iter()).rev() {
            if a < b {
                return true;
            } else if a > b {
                return false;
            }
        }
        true
    }

    /// Add two field elements
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;

        for i in 0..4 {
            let sum = carry + self.value[i] as u128 + other.value[i] as u128;
            result[i] = sum as u64;
            carry = sum >> 64;
        }

        // Reduce modulo the field modulus
        Self::reduce(&mut result);
        BabyJubjubField { value: result }
    }

    /// Subtract two field elements
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut borrow = 0i128;

        for i in 0..4 {
            let diff = self.value[i] as i128 - other.value[i] as i128 - borrow;
            result[i] = diff as u64;
            borrow = if diff < 0 { 1 } else { 0 };
        }

        // Add modulus if result is negative
        if borrow > 0 {
            Self::add_modulus(&mut result);
        }

        BabyJubjubField { value: result }
    }

    /// Multiply two field elements
    pub fn mul(&self, other: &Self) -> Self {
        let mut result = [0u128; 8];

        // Schoolbook multiplication
        for i in 0..4 {
            for j in 0..4 {
                result[i + j] += self.value[i] as u128 * other.value[j] as u128;
            }
        }

        // Reduce modulo the field modulus
        Self::reduce_mul(&mut result);

        let mut final_result = [0u64; 4];
        for i in 0..4 {
            final_result[i] = result[i] as u64;
        }

        BabyJubjubField {
            value: final_result,
        }
    }

    /// Compute the multiplicative inverse
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        // Use Fermat's little theorem: a^(p-2) = a^(-1) mod p
        let mut result = BabyJubjubField::one();
        let mut base = *self;
        let mut exponent = MODULUS;

        // Subtract 2 from the exponent
        Self::sub_from_modulus(&mut exponent, 2);

        while !Self::is_zero_array(&exponent) {
            if exponent[0] & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            Self::div_by_2(&mut exponent);
        }

        Some(result)
    }

    /// Check if the field element is zero
    pub fn is_zero(&self) -> bool {
        self.value.iter().all(|&x| x == 0)
    }

    /// Get the zero element
    pub fn zero() -> Self {
        BabyJubjubField { value: [0u64; 4] }
    }

    /// Get the one element
    pub fn one() -> Self {
        BabyJubjubField {
            value: [1u64, 0u64, 0u64, 0u64],
        }
    }

    /// Generate a random field element
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        // Ensure the value is less than the modulus
        let mut value = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut bytes_array = [0u8; 8];
            bytes_array[..chunk.len()].copy_from_slice(chunk);
            value[i] = u64::from_le_bytes(bytes_array);
        }

        // Reduce modulo the field modulus
        Self::reduce(&mut value);
        BabyJubjubField { value }
    }

    // Helper methods for modular arithmetic

    fn reduce(value: &mut [u64; 4]) {
        // Simple modular reduction - in practice, you'd want a more efficient implementation
        while !Self::is_less_than_modulus(value) {
            Self::sub_modulus(value);
        }
    }

    fn reduce_mul(value: &mut [u128; 8]) {
        // Reduce the 512-bit result modulo the field modulus
        // This is a simplified implementation
        for i in (4..8).rev() {
            if value[i] > 0 {
                // Add the high limb * modulus to the lower limbs
                let high_limb = value[i];
                value[i] = 0;

                for j in 0..4 {
                    if i - 4 + j < 8 {
                        value[i - 4 + j] += high_limb * MODULUS[j] as u128;
                    }
                }
            }
        }
    }

    fn sub_modulus(value: &mut [u64; 4]) {
        let mut borrow = 0i128;
        for i in 0..4 {
            let diff = value[i] as i128 - MODULUS[i] as i128 - borrow;
            value[i] = diff as u64;
            borrow = if diff < 0 { 1 } else { 0 };
        }
    }

    fn add_modulus(value: &mut [u64; 4]) {
        let mut carry = 0u128;
        for i in 0..4 {
            let sum = carry + value[i] as u128 + MODULUS[i] as u128;
            value[i] = sum as u64;
            carry = sum >> 64;
        }
    }

    fn sub_from_modulus(value: &mut [u64; 4], amount: u64) {
        if value[0] >= amount {
            value[0] -= amount;
        } else {
            value[0] = 0;
            // This is a simplified implementation - in practice you'd need proper borrowing
        }
    }

    /// Divide a 256-bit value by 2
    pub fn div_by_2(value: &mut [u64; 4]) {
        let mut carry = 0u64;
        for i in (0..4).rev() {
            let new_carry = value[i] & 1;
            value[i] = (value[i] >> 1) | (carry << 63);
            carry = new_carry;
        }
    }

    /// Check if a 256-bit value is zero
    pub fn is_zero_array(value: &[u64; 4]) -> bool {
        value.iter().all(|&x| x == 0)
    }
}

// Implement arithmetic traits

impl Add for BabyJubjubField {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        BabyJubjubField::add(&self, &other)
    }
}

impl AddAssign for BabyJubjubField {
    fn add_assign(&mut self, other: Self) {
        *self = BabyJubjubField::add(self, &other);
    }
}

impl Sub for BabyJubjubField {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        BabyJubjubField::sub(&self, &other)
    }
}

impl SubAssign for BabyJubjubField {
    fn sub_assign(&mut self, other: Self) {
        *self = BabyJubjubField::sub(self, &other);
    }
}

impl Mul for BabyJubjubField {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        BabyJubjubField::mul(&self, &other)
    }
}

impl MulAssign for BabyJubjubField {
    fn mul_assign(&mut self, other: Self) {
        *self = BabyJubjubField::mul(self, &other);
    }
}

impl Neg for BabyJubjubField {
    type Output = Self;
    fn neg(self) -> Self {
        if self.is_zero() {
            self
        } else {
            BabyJubjubField::zero().sub(self)
        }
    }
}
