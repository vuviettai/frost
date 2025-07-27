use criterion::{criterion_group, criterion_main, Criterion};
use frost_babyjubjub::*;
use std::hint::black_box;

fn bench_babyjubjub(c: &mut Criterion) {
    let mut rng = rand_core::OsRng;

    c.bench_function("babyjubjub_key_generation", |b| {
        b.iter(|| {
            let (shares, _pubkeys) = keys::generate_with_dealer(
                black_box(3),
                black_box(2),
                frost_core::keys::IdentifierList::Default,
                &mut rng,
            )
            .unwrap();
            black_box(shares);
        });
    });

    c.bench_function("babyjubjub_signing", |b| {
        let (shares, _pubkeys) =
            keys::generate_with_dealer(3, 2, frost_core::keys::IdentifierList::Default, &mut rng)
                .unwrap();

        let secret_share = shares.values().next().unwrap().clone();
        let key_package = keys::KeyPackage::try_from(secret_share).unwrap();
        let (nonces, commitments) = round1::commit(&key_package.signing_share(), &mut rng);

        let message = b"Hello, FROST!";
        let signing_package = SigningPackage::new(
            [(key_package.identifier().clone(), commitments)]
                .into_iter()
                .collect(),
            message,
        );

        b.iter(|| {
            let signature_share = round2::sign(
                black_box(&signing_package),
                black_box(&nonces),
                black_box(&key_package),
            )
            .unwrap();
            black_box(signature_share);
        });
    });
}

criterion_group!(benches, bench_babyjubjub);
criterion_main!(benches);
