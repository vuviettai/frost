#![no_std]
#![allow(non_snake_case)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![doc = document_features::document_features!()]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

#[macro_use]
mod util;
mod babyjubjub;

pub use babyjubjub::{BabyJubjubProjective, BabyJubjubScalar};
use frost_rerandomized::RandomizedCiphersuite;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256, Sha512};

use frost_core as frost;

#[cfg(test)]
mod tests;

// Re-exports in our public API
#[cfg(feature = "serde")]
pub use frost_core::serde;
pub use frost_core::{Ciphersuite, Field, FieldError, Group, GroupError};
pub use rand_core;

/// An error.
pub type Error = frost_core::Error<BabyJubjubSha256>;

/// An error for the SHA-512 variant.
pub type ErrorSha512 = frost_core::Error<BabyJubjubSha512>;

/// An implementation of the FROST(Baby Jubjub, SHA-256) ciphersuite scalar field.
#[derive(Clone, Copy)]
pub struct BabyJubjubScalarField;

impl Field for BabyJubjubScalarField {
    type Scalar = BabyJubjubScalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        BabyJubjubScalar::zero()
    }

    fn one() -> Self::Scalar {
        BabyJubjubScalar::one()
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
        scalar.invert()
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        BabyJubjubScalar::random(rng)
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, FieldError> {
        match BabyJubjubScalar::from_bytes(buf) {
            Some(s) => Ok(s),
            None => Err(FieldError::MalformedScalar),
        }
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        Self::serialize(scalar)
    }
}

/// An implementation of the FROST(Baby Jubjub, SHA-256) ciphersuite group.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BabyJubjubGroup;

impl Group for BabyJubjubGroup {
    type Field = BabyJubjubScalarField;

    type Element = BabyJubjubProjective;

    type Serialization = [u8; 32];

    fn cofactor() -> <Self::Field as Field>::Scalar {
        // Note: BabyJubjub curve has a cofactor of 8, which makes it unsuitable
        // for threshold signatures in its current form. This implementation is experimental.
        // The curve order is 8 times the subgroup order, which causes issues with
        // threshold signature schemes that expect a prime-order group.
        BabyJubjubScalar::one()
    }

    fn identity() -> Self::Element {
        BabyJubjubProjective::identity()
    }

    fn generator() -> Self::Element {
        BabyJubjubProjective::generator()
    }

    fn serialize(element: &Self::Element) -> Result<Self::Serialization, GroupError> {
        if *element == Self::identity() {
            return Err(GroupError::InvalidIdentityElement);
        }
        Ok(element.to_bytes())
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, GroupError> {
        match BabyJubjubProjective::from_bytes(buf) {
            Some(point) => {
                if point == Self::identity() {
                    Err(GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            }
            None => Err(GroupError::MalformedElement),
        }
    }
}

/// Context string from the ciphersuite in the [spec].
///
/// [spec]: https://datatracker.ietf.org/doc/html/rfc9591#section-6.5-1
const CONTEXT_STRING: &str = "FROST-BabyJubjub-SHA256-v1";

/// Context string for SHA-512 variant.
const CONTEXT_STRING_SHA512: &str = "FROST-BabyJubjub-SHA512-v1";

/// An implementation of the FROST(Baby Jubjub, SHA-256/512) ciphersuite.
/// The const parameter `HASH_SIZE` determines the hash function:
/// - `32` for SHA-256
/// - `64` for SHA-512
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BabyJubjubSha<const HASH_SIZE: usize>;

trait HashFunction {
    fn hash(inputs: &[&[u8]]) -> Vec<u8>;
}

struct Sha256Hash;
struct Sha512Hash;

impl HashFunction for Sha256Hash {
    fn hash(inputs: &[&[u8]]) -> Vec<u8> {
        let mut h = Sha256::new();
        for i in inputs {
            h.update(i);
        }
        h.finalize().to_vec()
    }
}

impl HashFunction for Sha512Hash {
    fn hash(inputs: &[&[u8]]) -> Vec<u8> {
        let mut h = Sha512::new();
        for i in inputs {
            h.update(i);
        }
        h.finalize().to_vec()
    }
}

impl<const HASH_SIZE: usize> BabyJubjubSha<HASH_SIZE> {
    const fn context_string() -> &'static str {
        match HASH_SIZE {
            32 => CONTEXT_STRING,
            64 => CONTEXT_STRING_SHA512,
            _ => panic!("HASH_SIZE must be 32 (SHA-256) or 64 (SHA-512)"),
        }
    }

    fn hash_to_array(inputs: &[&[u8]]) -> [u8; HASH_SIZE] {
        let hash_bytes = if HASH_SIZE == 32 {
            Sha256Hash::hash(inputs)
        } else if HASH_SIZE == 64 {
            Sha512Hash::hash(inputs)
        } else {
            panic!("HASH_SIZE must be 32 (SHA-256) or 64 (SHA-512)");
        };

        let mut output = [0u8; HASH_SIZE];
        output.copy_from_slice(&hash_bytes[..HASH_SIZE]);
        output
    }

    fn hash_to_scalar(inputs: &[&[u8]]) -> BabyJubjubScalar {
        let output = Self::hash_to_array(inputs);
        BabyJubjubScalar::from_bytes_mod_order_wide(&output)
    }
}

impl<const HASH_SIZE: usize> Ciphersuite for BabyJubjubSha<HASH_SIZE> {
    const ID: &'static str = Self::context_string();

    type Group = BabyJubjubGroup;

    type HashOutput = [u8; HASH_SIZE];

    type SignatureSerialization = [u8; 64];

    /// H1 for FROST(Baby Jubjub, SHA-256/512)
    fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        Self::hash_to_scalar(&[Self::context_string().as_bytes(), b"rho", m])
    }

    /// H2 for FROST(Baby Jubjub, SHA-256/512)
    fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        Self::hash_to_scalar(&[m])
    }

    /// H3 for FROST(Baby Jubjub, SHA-256/512)
    fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
        Self::hash_to_scalar(&[Self::context_string().as_bytes(), b"nonce", m])
    }

    /// H4 for FROST(Baby Jubjub, SHA-256/512)
    fn H4(m: &[u8]) -> Self::HashOutput {
        Self::hash_to_array(&[Self::context_string().as_bytes(), b"msg", m])
    }

    /// H5 for FROST(Baby Jubjub, SHA-256/512)
    fn H5(m: &[u8]) -> Self::HashOutput {
        Self::hash_to_array(&[Self::context_string().as_bytes(), b"com", m])
    }

    /// HDKG for FROST(Baby Jubjub, SHA-256/512)
    fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(Self::hash_to_scalar(&[
            Self::context_string().as_bytes(),
            b"dkg",
            m,
        ]))
    }

    /// HID for FROST(Baby Jubjub, SHA-256/512)
    fn HID(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(Self::hash_to_scalar(&[
            Self::context_string().as_bytes(),
            b"id",
            m,
        ]))
    }
}

impl<const HASH_SIZE: usize> RandomizedCiphersuite for BabyJubjubSha<HASH_SIZE> {
    fn hash_randomizer(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
        Some(Self::hash_to_scalar(&[
            Self::context_string().as_bytes(),
            b"randomizer",
            m,
        ]))
    }
}

// Type aliases for convenience
/// FROST(Baby Jubjub, SHA-256) ciphersuite.
pub type BabyJubjubSha256 = BabyJubjubSha<32>;

/// FROST(Baby Jubjub, SHA-512) ciphersuite.
pub type BabyJubjubSha512 = BabyJubjubSha<64>;

/// An identifier for a participant.
pub type Identifier256 = frost::Identifier<BabyJubjubSha256>;

/// A signing key for a single participant.
pub type SigningKey256 = frost_core::SigningKey<BabyJubjubSha256>;

/// A verifying key for a single participant.
pub type VerifyingKey256 = frost_core::VerifyingKey<BabyJubjubSha256>;

/// A Schnorr signature.
pub type Signature256 = frost_core::Signature<BabyJubjubSha256>;

/// An identifier for a participant (SHA-512 variant).
pub type IdentifierSha512 = frost::Identifier<BabyJubjubSha512>;

/// A Schnorr signature (SHA-512 variant).
pub type SignatureSha512 = frost_core::Signature<BabyJubjubSha512>;

/// A signing key for a single participant (SHA-512 variant).
pub type SigningKeySha512 = frost_core::SigningKey<BabyJubjubSha512>;

/// A verifying key for a single participant (SHA-512 variant).
pub type VerifyingKeySha512 = frost_core::VerifyingKey<BabyJubjubSha512>;

/// FROST(Baby Jubjub, SHA-256) key generation and key sharing.
pub mod keys {
    use super::*;

    /// A list of identifiers for participants.
    pub type IdentifierList<'a> = frost::keys::IdentifierList<'a, BabyJubjubSha256>;

    /// Generate a key package for a single participant.
    pub fn generate_with_dealer<RNG: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        mut rng: RNG,
    ) -> Result<(BTreeMap<Identifier256, SecretShare>, PublicKeyPackage), Error> {
        frost::keys::generate_with_dealer::<BabyJubjubSha256, RNG>(
            max_signers,
            min_signers,
            identifiers,
            &mut rng,
        )
    }

    /// Split an existing key into shares.
    pub fn split<R: RngCore + CryptoRng>(
        secret: &SigningKey256,
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        rng: &mut R,
    ) -> Result<(BTreeMap<Identifier256, SecretShare>, PublicKeyPackage), Error> {
        frost::keys::split::<BabyJubjubSha256, R>(
            secret,
            max_signers,
            min_signers,
            identifiers,
            rng,
        )
    }

    /// Reconstruct a secret from shares.
    pub fn reconstruct(secret_shares: &[KeyPackage]) -> Result<SigningKey256, Error> {
        frost::keys::reconstruct::<BabyJubjubSha256>(secret_shares)
    }

    /// A secret share generated by performing a (t-out-of-n) secret sharing scheme
    /// where n is the total number of shares and t is the threshold required to
    /// reconstruct the secret.
    pub type SecretShare = frost::keys::SecretShare<BabyJubjubSha256>;

    /// A signing share generated by performing a (t-out-of-n) secret sharing scheme
    /// where n is the total number of shares and t is the threshold required to
    /// reconstruct the secret.
    pub type SigningShare = frost::keys::SigningShare<BabyJubjubSha256>;

    /// A verification share for a participant.
    pub type VerifyingShare = frost::keys::VerifyingShare<BabyJubjubSha256>;

    /// A key package that contains the signing key share for a participant.
    pub type KeyPackage = frost::keys::KeyPackage<BabyJubjubSha256>;

    /// A public key package that contains the verifying keys for all participants.
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<BabyJubjubSha256>;

    /// A commitment to a secret sharing polynomial.
    pub type VerifiableSecretSharingCommitment =
        frost::keys::VerifiableSecretSharingCommitment<BabyJubjubSha256>;

    /// Distributed Key Generation (DKG) functionality.
    pub mod dkg;
    /// Key refresh functionality.
    pub mod refresh;
    /// Repairable secret sharing functionality.
    pub mod repairable;
}

/// FROST(Baby Jubjub, SHA-512) key generation and key sharing.
pub mod keys_sha512 {
    use super::*;

    /// A list of identifiers for participants (SHA-512 variant).
    pub type IdentifierList<'a> = frost::keys::IdentifierList<'a, BabyJubjubSha512>;

    /// Generate a key package for a single participant (SHA-512 variant).
    pub fn generate_with_dealer<RNG: RngCore + CryptoRng>(
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        mut rng: RNG,
    ) -> Result<(BTreeMap<IdentifierSha512, SecretShare>, PublicKeyPackage), ErrorSha512> {
        frost::keys::generate_with_dealer::<BabyJubjubSha512, RNG>(
            max_signers,
            min_signers,
            identifiers,
            &mut rng,
        )
    }

    /// Split an existing key into shares (SHA-512 variant).
    pub fn split<R: RngCore + CryptoRng>(
        secret: &SigningKeySha512,
        max_signers: u16,
        min_signers: u16,
        identifiers: IdentifierList,
        rng: &mut R,
    ) -> Result<(BTreeMap<IdentifierSha512, SecretShare>, PublicKeyPackage), ErrorSha512> {
        frost::keys::split::<BabyJubjubSha512, R>(
            secret,
            max_signers,
            min_signers,
            identifiers,
            rng,
        )
    }

    /// Reconstruct a secret from shares (SHA-512 variant).
    pub fn reconstruct(secret_shares: &[KeyPackage]) -> Result<SigningKeySha512, ErrorSha512> {
        frost::keys::reconstruct::<BabyJubjubSha512>(secret_shares)
    }

    /// A secret share generated by performing a (t-out-of-n) secret sharing scheme
    /// where n is the total number of shares and t is the threshold required to
    /// reconstruct the secret (SHA-512 variant).
    pub type SecretShare = frost::keys::SecretShare<BabyJubjubSha512>;

    /// A signing share generated by performing a (t-out-of-n) secret sharing scheme
    /// where n is the total number of shares and t is the threshold required to
    /// reconstruct the secret (SHA-512 variant).
    pub type SigningShare = frost::keys::SigningShare<BabyJubjubSha512>;

    /// A verification share for a participant (SHA-512 variant).
    pub type VerifyingShare = frost::keys::VerifyingShare<BabyJubjubSha512>;

    /// A key package that contains the signing key share for a participant (SHA-512 variant).
    pub type KeyPackage = frost::keys::KeyPackage<BabyJubjubSha512>;

    /// A public key package that contains the verifying keys for all participants (SHA-512 variant).
    pub type PublicKeyPackage = frost::keys::PublicKeyPackage<BabyJubjubSha512>;

    /// A commitment to a secret sharing polynomial (SHA-512 variant).
    pub type VerifiableSecretSharingCommitment =
        frost::keys::VerifiableSecretSharingCommitment<BabyJubjubSha512>;

    // Re-export the existing modules for SHA-512 variant
    pub use super::keys::{dkg, refresh, repairable};
}

/// FROST(Baby Jubjub, SHA-256) Round 1 functionality and types.
pub mod round1 {
    use super::*;

    /// A commitment to a single nonce.
    pub type NonceCommitment = frost::round1::NonceCommitment<BabyJubjubSha256>;

    /// A package that contains the nonces and commitments for a participant.
    pub type SigningNonces = frost::round1::SigningNonces<BabyJubjubSha256>;

    /// A package that contains the commitments for a participant.
    pub type SigningCommitments = frost::round1::SigningCommitments<BabyJubjubSha256>;

    /// Generate a new signing nonce and commitment.
    pub fn commit<RNG>(
        secret: &keys::SigningShare,
        rng: &mut RNG,
    ) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<BabyJubjubSha256, RNG>(secret, rng)
    }
}

/// A package that contains the signing commitments for all participants.
pub type SigningPackage = frost::SigningPackage<BabyJubjubSha256>;

/// FROST(Baby Jubjub, SHA-512) Round 1 functionality and types.
pub mod round1_sha512 {
    use super::*;

    /// A commitment to a single nonce (SHA-512 variant).
    pub type NonceCommitment = frost::round1::NonceCommitment<BabyJubjubSha512>;

    /// A package that contains the nonces and commitments for a participant (SHA-512 variant).
    pub type SigningNonces = frost::round1::SigningNonces<BabyJubjubSha512>;

    /// A package that contains the commitments for a participant (SHA-512 variant).
    pub type SigningCommitments = frost::round1::SigningCommitments<BabyJubjubSha512>;

    /// Generate a new signing nonce and commitment (SHA-512 variant).
    pub fn commit<RNG>(
        secret: &keys_sha512::SigningShare,
        rng: &mut RNG,
    ) -> (SigningNonces, SigningCommitments)
    where
        RNG: CryptoRng + RngCore,
    {
        frost::round1::commit::<BabyJubjubSha512, RNG>(secret, rng)
    }
}

/// A package that contains the signing commitments for all participants (SHA-512 variant).
pub type SigningPackageSha512 = frost::SigningPackage<BabyJubjubSha512>;

/// FROST(Baby Jubjub, SHA-256) Round 2 functionality and types.
pub mod round2 {
    use super::*;

    /// A signature share for a participant.
    pub type SignatureShare = frost::round2::SignatureShare<BabyJubjubSha256>;

    /// Generate a signature share.
    pub fn sign(
        signing_package: &SigningPackage,
        signer_nonces: &round1::SigningNonces,
        key_package: &keys::KeyPackage,
    ) -> Result<SignatureShare, Error> {
        frost::round2::sign::<BabyJubjubSha256>(signing_package, signer_nonces, key_package)
    }
}

/// FROST(Baby Jubjub, SHA-512) Round 2 functionality and types.
pub mod round2_sha512 {
    use super::*;

    /// A signature share for a participant (SHA-512 variant).
    pub type SignatureShare = frost::round2::SignatureShare<BabyJubjubSha512>;

    /// Generate a signature share (SHA-512 variant).
    pub fn sign(
        signing_package: &SigningPackageSha512,
        signer_nonces: &round1_sha512::SigningNonces,
        key_package: &keys_sha512::KeyPackage,
    ) -> Result<SignatureShare, ErrorSha512> {
        frost::round2::sign::<BabyJubjubSha512>(signing_package, signer_nonces, key_package)
    }
}

/// Aggregate signature shares into a signature.
pub fn aggregate(
    signing_package: &SigningPackage,
    signature_shares: &BTreeMap<Identifier256, round2::SignatureShare>,
    pubkeys: &keys::PublicKeyPackage,
) -> Result<Signature256, Error> {
    frost::aggregate::<BabyJubjubSha256>(signing_package, signature_shares, pubkeys)
}

/// Aggregate signature shares into a signature (SHA-512 variant).
pub fn aggregate_sha512(
    signing_package: &SigningPackageSha512,
    signature_shares: &BTreeMap<IdentifierSha512, round2_sha512::SignatureShare>,
    pubkeys: &keys_sha512::PublicKeyPackage,
) -> Result<SignatureSha512, ErrorSha512> {
    frost::aggregate::<BabyJubjubSha512>(signing_package, signature_shares, pubkeys)
}

#[cfg(test)]
mod sha512_tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_babyjubjub_sha512_ciphersuite() {
        // Test that the ciphersuite has the correct ID
        assert_eq!(BabyJubjubSha512::ID, "FROST-BabyJubjub-SHA512-v1");

        // Test that H4 produces 64-byte output
        let test_message = b"test message";
        let hash_output = BabyJubjubSha512::H4(test_message);
        assert_eq!(hash_output.len(), 64);

        // Test that H5 produces 64-byte output
        let hash_output_5 = BabyJubjubSha512::H5(test_message);
        assert_eq!(hash_output_5.len(), 64);

        // Test that H1, H2, H3 produce scalars
        let _scalar_1 = BabyJubjubSha512::H1(test_message);
        let _scalar_2 = BabyJubjubSha512::H2(test_message);
        let _scalar_3 = BabyJubjubSha512::H3(test_message);

        // Test HDKG and HID functions
        let dkg_output = BabyJubjubSha512::HDKG(test_message);
        let hid_output = BabyJubjubSha512::HID(test_message);
        assert!(dkg_output.is_some());
        assert!(hid_output.is_some());

        // Test RandomizedCiphersuite implementation
        let randomizer_output = BabyJubjubSha512::hash_randomizer(test_message);
        assert!(randomizer_output.is_some());
    }

    #[test]
    fn test_babyjubjub_sha256_ciphersuite() {
        // Test that the ciphersuite has the correct ID
        assert_eq!(BabyJubjubSha256::ID, "FROST-BabyJubjub-SHA256-v1");

        // Test that H4 produces 32-byte output
        let test_message = b"test message";
        let hash_output = BabyJubjubSha256::H4(test_message);
        assert_eq!(hash_output.len(), 32);

        // Test that H5 produces 32-byte output
        let hash_output_5 = BabyJubjubSha256::H5(test_message);
        assert_eq!(hash_output_5.len(), 32);

        // Test that H1, H2, H3 produce scalars
        let _scalar_1 = BabyJubjubSha256::H1(test_message);
        let _scalar_2 = BabyJubjubSha256::H2(test_message);
        let _scalar_3 = BabyJubjubSha256::H3(test_message);

        // Test HDKG and HID functions
        let dkg_output = BabyJubjubSha256::HDKG(test_message);
        let hid_output = BabyJubjubSha256::HID(test_message);
        assert!(dkg_output.is_some());
        assert!(hid_output.is_some());

        // Test RandomizedCiphersuite implementation
        let randomizer_output = BabyJubjubSha256::hash_randomizer(test_message);
        assert!(randomizer_output.is_some());
    }

    #[test]
    fn test_unified_struct() {
        // Test that both variants work correctly
        let test_message = b"test message";

        // SHA-256 variant
        let sha256_hash = BabyJubjubSha::<32>::H4(test_message);
        assert_eq!(sha256_hash.len(), 32);

        // SHA-512 variant
        let sha512_hash = BabyJubjubSha::<64>::H4(test_message);
        assert_eq!(sha512_hash.len(), 64);

        // Test that they produce different outputs (compare as slices)
        assert_ne!(&sha256_hash[..], &sha512_hash[..32]);
    }

    #[test]
    fn test_hash_to_array() {
        // Test hash_to_array for SHA-256 variant
        let inputs: &[&[u8]] = &[b"test", b"message", b"for", b"hashing"];
        let sha256_result = BabyJubjubSha::<32>::hash_to_array(inputs);
        assert_eq!(sha256_result.len(), 32);

        // Verify SHA-256 result is not all zeros
        assert_ne!(
            sha256_result, [0u8; 32],
            "SHA-256 result should not be all zeros"
        );

        // Test hash_to_array for SHA-512 variant
        let sha512_result = BabyJubjubSha::<64>::hash_to_array(inputs);
        assert_eq!(sha512_result.len(), 64);

        // Verify SHA-512 result is not all zeros
        assert_ne!(
            sha512_result, [0u8; 64],
            "SHA-512 result should not be all zeros"
        );

        // Test that different inputs produce different outputs
        let different_inputs: &[&[u8]] = &[b"different", b"message"];
        let sha256_different = BabyJubjubSha::<32>::hash_to_array(different_inputs);
        let sha512_different = BabyJubjubSha::<64>::hash_to_array(different_inputs);

        assert_ne!(sha256_result, sha256_different);
        assert_ne!(sha512_result, sha512_different);

        // Test that same inputs produce same outputs (deterministic)
        let sha256_result2 = BabyJubjubSha::<32>::hash_to_array(inputs);
        let sha512_result2 = BabyJubjubSha::<64>::hash_to_array(inputs);

        assert_eq!(sha256_result, sha256_result2);
        assert_eq!(sha512_result, sha512_result2);

        // Test with empty inputs
        let empty_inputs: &[&[u8]] = &[];
        let sha256_empty = BabyJubjubSha::<32>::hash_to_array(empty_inputs);
        let sha512_empty = BabyJubjubSha::<64>::hash_to_array(empty_inputs);

        assert_eq!(sha256_empty.len(), 32);
        assert_eq!(sha512_empty.len(), 64);

        // Verify empty input results are not all zeros
        assert_ne!(
            sha256_empty, [0u8; 32],
            "SHA-256 empty result should not be all zeros"
        );
        assert_ne!(
            sha512_empty, [0u8; 64],
            "SHA-512 empty result should not be all zeros"
        );
    }

    #[test]
    fn test_hash_to_scalar() {
        // Test hash_to_scalar for SHA-256 variant
        let inputs: &[&[u8]] = &[b"test", b"message", b"for", b"scalar"];
        let sha256_scalar = BabyJubjubSha::<32>::hash_to_scalar(inputs);

        // Test hash_to_scalar for SHA-512 variant
        let sha512_scalar = BabyJubjubSha::<64>::hash_to_scalar(inputs);

        // Test that different inputs produce different scalars
        let different_inputs: &[&[u8]] = &[b"different", b"scalar"];
        let sha256_different = BabyJubjubSha::<32>::hash_to_scalar(different_inputs);
        let sha512_different = BabyJubjubSha::<64>::hash_to_scalar(different_inputs);

        // Test that same inputs produce same scalars (deterministic)
        let sha256_scalar2 = BabyJubjubSha::<32>::hash_to_scalar(inputs);
        let sha512_scalar2 = BabyJubjubSha::<64>::hash_to_scalar(inputs);

        assert_eq!(sha256_scalar, sha256_scalar2);
        assert_eq!(sha512_scalar, sha512_scalar2);

        // Test with empty inputs
        let empty_inputs: &[&[u8]] = &[];
        let _sha256_empty = BabyJubjubSha::<32>::hash_to_scalar(empty_inputs);
        let _sha512_empty = BabyJubjubSha::<64>::hash_to_scalar(empty_inputs);

        // Test with some non-empty inputs
        let non_empty_inputs: &[&[u8]] = &[b"non-empty", b"input"];
        let sha256_non_empty = BabyJubjubSha::<32>::hash_to_scalar(non_empty_inputs);
        let sha512_non_empty = BabyJubjubSha::<64>::hash_to_scalar(non_empty_inputs);

        // Test that different inputs produce different results (when both are non-zero)
        if sha256_scalar != BabyJubjubScalar::zero() && sha256_different != BabyJubjubScalar::zero()
        {
            assert_ne!(sha256_scalar, sha256_different);
        }
        if sha512_scalar != BabyJubjubScalar::zero() && sha512_different != BabyJubjubScalar::zero()
        {
            assert_ne!(sha512_scalar, sha512_different);
        }

        // Test that SHA-256 and SHA-512 produce different scalars for same input (when both are non-zero)
        if sha256_scalar != BabyJubjubScalar::zero() && sha512_scalar != BabyJubjubScalar::zero() {
            assert_ne!(sha256_scalar, sha512_scalar);
        }

        // Test that the function is deterministic for the same inputs
        let sha256_non_empty2 = BabyJubjubSha::<32>::hash_to_scalar(non_empty_inputs);
        let sha512_non_empty2 = BabyJubjubSha::<64>::hash_to_scalar(non_empty_inputs);

        assert_eq!(sha256_non_empty, sha256_non_empty2);
        assert_eq!(sha512_non_empty, sha512_non_empty2);
    }

    #[test]
    fn test_hash_to_scalar_edge_cases() {
        // Test with very long input
        let long_input = vec![b'a'; 1000];
        let inputs: &[&[u8]] = &[&long_input[..]];

        let sha256_scalar = BabyJubjubSha::<32>::hash_to_scalar(inputs);
        let sha512_scalar = BabyJubjubSha::<64>::hash_to_scalar(inputs);

        // Test with binary data
        let binary_data = vec![0u8, 1u8, 255u8, 128u8, 64u8];
        let inputs: &[&[u8]] = &[&binary_data[..]];

        let sha256_scalar_binary = BabyJubjubSha::<32>::hash_to_scalar(inputs);
        let sha512_scalar_binary = BabyJubjubSha::<64>::hash_to_scalar(inputs);

        // Test with context string inputs (like the actual ciphersuite uses)
        let context_inputs: &[&[u8]] = &[BabyJubjubSha::<32>::context_string().as_bytes(), b"test"];
        let sha256_context = BabyJubjubSha::<32>::hash_to_scalar(context_inputs);

        let context_inputs_512: &[&[u8]] =
            &[BabyJubjubSha::<64>::context_string().as_bytes(), b"test"];
        let sha512_context = BabyJubjubSha::<64>::hash_to_scalar(context_inputs_512);

        // Test that different inputs produce different results (when both are non-zero)
        if sha256_scalar != BabyJubjubScalar::zero()
            && sha256_scalar_binary != BabyJubjubScalar::zero()
        {
            assert_ne!(sha256_scalar, sha256_scalar_binary);
        }
        if sha512_scalar != BabyJubjubScalar::zero()
            && sha512_scalar_binary != BabyJubjubScalar::zero()
        {
            assert_ne!(sha512_scalar, sha512_scalar_binary);
        }

        // Test that the function is deterministic for the same inputs
        let sha256_scalar2 = BabyJubjubSha::<32>::hash_to_scalar(&[&long_input[..]]);
        let sha512_scalar2 = BabyJubjubSha::<64>::hash_to_scalar(&[&long_input[..]]);

        assert_eq!(sha256_scalar, sha256_scalar2);
        assert_eq!(sha512_scalar, sha512_scalar2);

        // Test that context inputs produce different results from regular inputs (when both are non-zero)
        if sha256_context != BabyJubjubScalar::zero() && sha256_scalar != BabyJubjubScalar::zero() {
            assert_ne!(sha256_context, sha256_scalar);
        }
        if sha512_context != BabyJubjubScalar::zero() && sha512_scalar != BabyJubjubScalar::zero() {
            assert_ne!(sha512_context, sha512_scalar);
        }
    }

    #[test]
    fn test_hash_to_array_edge_cases() {
        // Test with very long input
        let long_input = vec![b'a'; 1000];
        let inputs: &[&[u8]] = &[&long_input[..]];

        let sha256_result = BabyJubjubSha::<32>::hash_to_array(inputs);
        let sha512_result = BabyJubjubSha::<64>::hash_to_array(inputs);

        assert_eq!(sha256_result.len(), 32);
        assert_eq!(sha512_result.len(), 64);

        // Test with binary data
        let binary_data = vec![0u8, 1u8, 255u8, 128u8, 64u8];
        let inputs: &[&[u8]] = &[&binary_data[..]];

        let sha256_result = BabyJubjubSha::<32>::hash_to_array(inputs);
        let sha512_result = BabyJubjubSha::<64>::hash_to_array(inputs);

        assert_eq!(sha256_result.len(), 32);
        assert_eq!(sha512_result.len(), 64);
    }
}
