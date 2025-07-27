use super::*;

/// Performs the first part of the distributed key generation protocol
/// for the given participant.
///
/// It returns the [`round1::SecretPackage`] that must be kept in memory
/// by the participant for the other steps, and the [`round1::Package`] that
/// must be sent to each other participant in the DKG run.
pub fn part1<R: RngCore + CryptoRng>(
    identifier: Identifier256,
    max_signers: u16,
    min_signers: u16,
    mut rng: R,
) -> Result<(dkg::round1::SecretPackage, dkg::round1::Package), Error> {
    frost::keys::dkg::part1(identifier, max_signers, min_signers, &mut rng)
}

/// Performs the second part of the distributed key generation protocol for the
/// participant holding the given [`round1::SecretPackage`], given the received
/// [`round1::Package`]s received from the other participants.
///
/// `round1_packages` maps the identifier of each other participant to the
/// [`round1::Package`] they sent to the current participant (the owner of
/// `secret_package`). These identifiers must come from whatever mapping the
/// coordinator has between communication channels and participants, i.e. they
/// must have assurance that the [`round1::Package`] came from the participant
/// with that identifier.
///
/// It returns the [`round2::SecretPackage`] that must be kept in memory by the
/// participant for the final step, and the map of [`round2::Package`]s that
/// must be sent to each other participant who has the given identifier in the
/// map key.
pub fn part2(
    secret_package: dkg::round1::SecretPackage,
    round1_packages: &BTreeMap<Identifier256, dkg::round1::Package>,
) -> Result<
    (
        dkg::round2::SecretPackage,
        BTreeMap<Identifier256, dkg::round2::Package>,
    ),
    Error,
> {
    frost::keys::dkg::part2(secret_package, round1_packages)
}

/// Performs the third and final part of the distributed key generation protocol
/// for the participant holding the given [`round2::SecretPackage`], given the
/// received [`round1::Package`]s and [`round2::Package`]s received from the
/// other participants.
///
/// `round1_packages` must be the same used in [`part2()`].
///
/// `round2_packages` maps the identifier of each other participant to the
/// [`round2::Package`] they sent to the current participant (the owner of
/// `secret_package`). These identifiers must come from whatever mapping the
/// coordinator has between communication channels and participants, i.e. they
/// must have assurance that the [`round2::Package`] came from the participant
/// with that identifier.
///
/// It returns the [`KeyPackage`] that has the long-lived key share for the
/// participant, and the [`PublicKeyPackage`]s that has public information about
/// all participants; both of which are required to compute FROST signatures.
pub fn part3(
    round2_secret_package: &dkg::round2::SecretPackage,
    round1_packages: &BTreeMap<Identifier256, dkg::round1::Package>,
    round2_packages: &BTreeMap<Identifier256, dkg::round2::Package>,
) -> Result<(KeyPackage, PublicKeyPackage), Error> {
    frost::keys::dkg::part3(round2_secret_package, round1_packages, round2_packages)
}
