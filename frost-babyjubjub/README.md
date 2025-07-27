# frost-babyjubjub

A Schnorr signature scheme over the Baby Jubjub curve that supports FROST.

## About

This crate provides an implementation of the FROST(Ed25519, SHA-512) ciphersuite.

## Usage

```rust
use frost_babyjubjub::BabyJubjubSha256;

// Generate key shares
let (shares, pubkeys) = frost_babyjubjub::keys::generate_with_dealer(
    3, // max_signers
    2, // min_signers
    &mut rng,
)?;

// Sign a message
let signing_package = frost_babyjubjub::SigningPackage::new(
    signing_commitments,
    &message,
);

let signature_share = frost_babyjubjub::round2::sign(
    &signing_package,
    &signing_nonces,
    &key_package,
)?;

// Aggregate the signature
let signature = frost_babyjubjub::aggregate(
    &signing_package,
    &signature_shares,
    &pubkeys,
)?;
```

## Features

- `serialization`: Enable `serde` support for types that need to be communicated
- `cheater-detection`: Enable cheater detection during signature aggregation

## Security

This crate has not been audited and is provided as-is for experimental purposes.
