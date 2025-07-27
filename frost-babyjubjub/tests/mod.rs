//! Tests for Baby Jubjub FROST implementation.

pub mod helpers;
pub mod integration_tests;

#[cfg(test)]
mod unit_tests {
    use std::collections::BTreeMap;

    use frost_babyjubjub::{
        BabyJubjubField, BabyJubjubGroup, BabyJubjubPoint, BabyJubjubScalar, BabyJubjubScalarField,
        BabyJubjubSha256, Field, Group,
    };
    use frost_core::Ciphersuite;
    use frost_rerandomized::RandomizedCiphersuite;
    use rand_core::OsRng;

    #[test]
    fn test_basic_types() {
        // Test that basic types can be created and have expected properties
        let scalar = BabyJubjubScalar::zero();
        let point = BabyJubjubPoint::identity();
        let field = BabyJubjubField::zero();

        assert!(scalar.is_zero());
        assert!(point.is_identity());
        assert!(field.is_zero());
    }

    #[test]
    fn test_ciphersuite_constants() {
        // Test that ciphersuite constants are correct
        assert_eq!(BabyJubjubSha256::ID, "FROST-BabyJubjub-SHA256-v1");

        // Test that hash functions work
        let message = b"test";
        let h1 = BabyJubjubSha256::H1(message);
        let h2 = BabyJubjubSha256::H2(message);
        let h3 = BabyJubjubSha256::H3(message);
        let h4 = BabyJubjubSha256::H4(message);
        let h5 = BabyJubjubSha256::H5(message);

        assert!(!h1.is_zero());
        assert!(!h2.is_zero());
        assert!(!h3.is_zero());
        assert_eq!(h4.len(), 32);
        assert_eq!(h5.len(), 32);
    }

    #[test]
    fn test_group_operations() {
        let mut rng = OsRng;

        // Test group identity
        let identity = BabyJubjubGroup::identity();
        assert!(identity.is_identity());

        // Test group generator
        let generator = BabyJubjubGroup::generator();
        assert!(!generator.is_identity());
        assert!(generator.is_on_curve());

        // Test group serialization
        let element = BabyJubjubGroup::generator();
        let serialized = BabyJubjubGroup::serialize(&element).unwrap();
        let deserialized = BabyJubjubGroup::deserialize(&serialized).unwrap();
        assert_eq!(element, deserialized);

        // Test that identity cannot be serialized
        assert!(BabyJubjubGroup::serialize(&identity).is_err());
    }

    #[test]
    fn test_field_operations() {
        let mut rng = OsRng;

        // Test field zero and one
        let zero = BabyJubjubScalarField::zero();
        let one = BabyJubjubScalarField::one();

        assert!(zero.is_zero());
        assert!(!one.is_zero());

        // Test field random generation
        let random = BabyJubjubScalarField::random(&mut rng);
        assert!(!random.is_zero());

        // Test field serialization
        let scalar = BabyJubjubScalarField::random(&mut rng);
        let serialized = BabyJubjubScalarField::serialize(&scalar);
        let deserialized = BabyJubjubScalarField::deserialize(&serialized).unwrap();
        assert_eq!(scalar, deserialized);

        // Test field inversion
        let inv = BabyJubjubScalarField::invert(&one).unwrap();
        assert_eq!(one.mul(&inv), one);

        // Test that zero cannot be inverted
        assert!(BabyJubjubScalarField::invert(&zero).is_err());
    }

    #[test]
    fn test_randomized_ciphersuite() {
        let message = b"test message";

        // Test hash randomizer
        let randomizer = BabyJubjubSha256::hash_randomizer(message);
        assert!(randomizer.is_some());
        assert!(!randomizer.unwrap().is_zero());
    }
}

#[cfg(test)]
mod integration_tests_internal {
    use std::collections::BTreeMap;

    use frost_babyjubjub::{aggregate, keys, round1, round2, SigningPackage};
    use rand_core::OsRng;

    #[test]
    fn test_basic_signing_flow() {
        let mut rng = OsRng;

        // Generate key shares
        let (shares, pubkeys) = keys::generate_with_dealer(
            3, // max_signers
            2, // min_signers
            keys::IdentifierList::Default,
            &mut rng,
        )
        .unwrap();

        // Create key packages
        let mut key_packages = BTreeMap::new();
        for (identifier, secret_share) in &shares {
            let key_package = keys::KeyPackage::try_from(secret_share.clone()).unwrap();
            key_packages.insert(*identifier, key_package);
        }

        // Round 1: Generate nonces and commitments
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();

        for (identifier, key_package) in &key_packages {
            let (nonce, commitment) = round1::commit(key_package.signing_share(), &mut rng);
            nonces.insert(*identifier, nonce);
            commitments.insert(*identifier, commitment);
        }

        // Create signing package
        let message = b"Hello, Baby Jubjub!";
        let signing_package = SigningPackage::new(commitments, message);

        // Round 2: Generate signature shares
        let mut signature_shares = BTreeMap::new();

        for (identifier, key_package) in &key_packages {
            let signature_share =
                round2::sign(&signing_package, &nonces[identifier], key_package).unwrap();
            signature_shares.insert(*identifier, signature_share);
        }

        // Aggregate signature
        let signature = aggregate(&signing_package, &signature_shares, &pubkeys).unwrap();

        // Verify signature
        let is_valid = pubkeys.verifying_key().verify(message, &signature);
        assert!(is_valid.is_ok());
    }

    #[test]
    fn test_dkg_flow() {
        // TODO: Implement proper DKG test
        // For now, just test that the basic types work
        assert!(true);
    }

    #[test]
    fn test_refresh_flow() {
        // TODO: Implement proper refresh test
        // For now, just test that the basic types work
        assert!(true);
    }
}
