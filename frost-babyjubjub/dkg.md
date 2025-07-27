# Distributed Key Generation (DKG)

This module provides functionality for performing distributed key generation (DKG) for the Baby Jubjub curve.

## Overview

DKG allows a group of participants to jointly generate a secret key without any single participant learning the complete secret. This is useful for threshold signature schemes where no single party should have access to the full signing key.

## Protocol

The DKG protocol consists of three rounds:

1. **Round 1**: Each participant generates a secret polynomial and broadcasts commitments to it.
2. **Round 2**: Each participant sends shares of their secret to other participants.
3. **Round 3**: Each participant verifies the shares they received and computes their final key share.

## Usage

```rust
use frost_babyjubjub::keys::dkg;

// Round 1
let (secret_package, package) = dkg::part1(
    identifier,
    max_signers,
    min_signers,
    &mut rng,
)?;

// Round 2
let (round2_secret_package, round2_packages) = dkg::part2(
    secret_package,
    &round1_packages,
)?;

// Round 3
let (key_package, public_key_package) = dkg::part3(
    &round2_secret_package,
    &round1_packages,
    &round2_packages,
)?;
```

## Security Considerations

- All secret packages must be kept confidential and never shared with other participants.
- Communication channels must be authenticated and confidential.
- The protocol assumes a synchronous network model.
