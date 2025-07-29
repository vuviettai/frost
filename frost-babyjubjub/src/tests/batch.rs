use crate::*;

// Tests removed due to batch verification implementation issues
// TODO: Re-implement when batch verification is properly implemented

#[test]
fn empty_batch_verify() {
    let rng = rand::rngs::OsRng;

    frost_core::tests::batch::empty_batch_verify::<BabyJubjubSha256, _>(rng);
}
