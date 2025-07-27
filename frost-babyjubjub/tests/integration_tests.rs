use std::collections::BTreeMap;

use frost_babyjubjub::*;
use lazy_static::lazy_static;
use serde_json::Value;

#[test]
fn check_zero_key_fails() {
    frost_core::tests::ciphersuite_generic::check_zero_key_fails::<BabyJubjubSha256>();
}

#[test]
fn check_sign_with_dkg() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_sign_with_dkg::<BabyJubjubSha256, _>(rng);
}

#[test]
fn check_rts() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::repairable::check_rts::<BabyJubjubSha256, _>(rng);
}

#[test]
fn check_refresh_shares_with_dealer() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::refresh::check_refresh_shares_with_dealer::<BabyJubjubSha256, _>(rng);
}

#[test]
fn check_refresh_shares_with_dealer_serialisation() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::refresh::check_refresh_shares_with_dealer_serialisation::<BabyJubjubSha256, _>(
        rng,
    );
}

#[test]
fn check_refresh_shares_with_dealer_fails_with_invalid_public_key_package() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::refresh::check_refresh_shares_with_dealer_fails_with_invalid_public_key_package::<BabyJubjubSha256, _>(rng);
}

#[test]
fn check_sign_with_dealer() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_sign_with_dealer::<BabyJubjubSha256, _>(rng);
}

#[test]
fn check_sign_with_dealer_fails_with_invalid_signers() {
    let rng = rand::rngs::OsRng;
    let min_signers = 1;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;
    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_fails_with_invalid_signers::<
        BabyJubjubSha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_share_generation_babyjubjub_sha256() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_share_generation::<BabyJubjubSha256, _>(rng);
}

#[test]
fn check_share_generation_fails_with_invalid_signers() {
    let rng = rand::rngs::OsRng;
    let min_signers = 0;
    let max_signers = 3;
    let error = Error::InvalidMinSigners;
    frost_core::tests::ciphersuite_generic::check_share_generation_fails_with_invalid_signers::<
        BabyJubjubSha256,
        _,
    >(min_signers, max_signers, error, rng);
}

#[test]
fn check_error_culprit() {
    frost_core::tests::ciphersuite_generic::check_error_culprit::<BabyJubjubSha256>();
}

#[test]
fn check_identifier_derivation() {
    frost_core::tests::ciphersuite_generic::check_identifier_derivation::<BabyJubjubSha256>();
}

#[test]
fn check_sign_with_dealer_and_identifiers() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_sign_with_dealer_and_identifiers::<
        BabyJubjubSha256,
        _,
    >(rng);
}

#[test]
fn check_sign_with_missing_identifier() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_sign_with_missing_identifier::<BabyJubjubSha256, _>(
        rng,
    );
}

#[test]
fn check_sign_with_incorrect_commitments() {
    let rng = rand::rngs::OsRng;
    frost_core::tests::ciphersuite_generic::check_sign_with_incorrect_commitments::<
        BabyJubjubSha256,
        _,
    >(rng);
}

// Custom Baby Jubjub specific tests
#[test]
fn test_babyjubjub_basic_signing() {
    let mut rng = rand::rngs::OsRng;

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
fn test_babyjubjub_field_operations() {
    let mut rng = rand::rngs::OsRng;

    // Test field arithmetic
    let a = BabyJubjubField::random(&mut rng);
    let b = BabyJubjubField::random(&mut rng);
    let zero = BabyJubjubField::zero();
    let one = BabyJubjubField::one();

    // Test addition
    let sum = a + b;
    assert_eq!(sum, b + a); // Commutativity

    // Test identity
    assert_eq!(a + zero, a);
    assert_eq!(zero + a, a);

    // Test negation
    let neg_a = -a;
    assert_eq!(a + neg_a, zero);

    // Test multiplication
    let product = a * b;
    assert_eq!(product, b * a); // Commutativity

    // Test multiplicative identity
    assert_eq!(a * one, a);
    assert_eq!(one * a, a);

    // Test multiplicative zero
    assert_eq!(a * zero, zero);
    assert_eq!(zero * a, zero);
}

#[test]
fn test_babyjubjub_scalar_operations() {
    let mut rng = rand::rngs::OsRng;

    // Test scalar arithmetic
    let a = BabyJubjubScalar::random(&mut rng);
    let b = BabyJubjubScalar::random(&mut rng);
    let zero = BabyJubjubScalar::zero();
    let one = BabyJubjubScalar::one();

    // Test addition
    let sum = a + b;
    assert_eq!(sum, b + a); // Commutativity

    // Test identity
    assert_eq!(a + zero, a);
    assert_eq!(zero + a, a);

    // Test negation
    let neg_a = -a;
    assert_eq!(a + neg_a, zero);

    // Test multiplication
    let product = a * b;
    assert_eq!(product, b * a); // Commutativity

    // Test multiplicative identity
    assert_eq!(a * one, a);
    assert_eq!(one * a, a);

    // Test multiplicative zero
    assert_eq!(a * zero, zero);
    assert_eq!(zero * a, zero);
}

#[test]
fn test_babyjubjub_point_operations() {
    let mut rng = rand::rngs::OsRng;

    // Test point arithmetic
    let generator = BabyJubjubPoint::generator();
    let identity = BabyJubjubPoint::identity();

    // Test identity
    assert_eq!(generator + identity, generator);
    assert_eq!(identity + generator, generator);

    // Test doubling
    let doubled = generator + generator;
    assert_eq!(doubled, generator.double());

    // Test scalar multiplication
    let scalar = BabyJubjubScalar::random(&mut rng);
    let point = generator * scalar;
    assert!(point.is_on_curve());

    // Test zero scalar
    let zero_scalar = BabyJubjubScalar::zero();
    let zero_point = generator * zero_scalar;
    assert_eq!(zero_point, identity);
}
