//! Test helpers for Baby Jubjub FROST implementation.

use frost_babyjubjub::{keys, round1, Identifier256};
use rand_core::OsRng;

/// Generate a test key package for a given identifier
pub fn generate_test_key_package(identifier: u16) -> keys::KeyPackage {
    let mut rng = OsRng;
    let (shares, _) = keys::generate_with_dealer(
        3, // max_signers
        2, // min_signers
        keys::IdentifierList::Default,
        &mut rng,
    )
    .unwrap();

    let secret_share = shares
        .get(&Identifier256::try_from(identifier).unwrap())
        .unwrap();
    keys::KeyPackage::try_from(secret_share.clone()).unwrap()
}

/// Generate test signing nonces and commitments
pub fn generate_test_nonces_and_commitments(
    key_package: &keys::KeyPackage,
) -> (round1::SigningNonces, round1::SigningCommitments) {
    let mut rng = OsRng;
    round1::commit(key_package.signing_share(), &mut rng)
}

// TODO: Implement additional test helpers as needed
