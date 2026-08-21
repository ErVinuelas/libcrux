use criterion::{criterion_group, criterion_main, Criterion};

// A valid (secret key, public key) pair taken from the Wycheproof
// secp384r1 ECDH test vectors (tcId 1).
const SK: &str = "766e61425b2da9f846c09fc3564b93a6f8603b7392c785165bf20da948c49fd1fb1dee4edd64356b9f21c588b75dfd81";
const PK: &str = "04790a6e059ef9a5940163183d4a7809135d29791643fc43a2f17ee8bf677ab84f791b64a6be15969ffa012dd9185d8796d9b954baa8a75e82df711b3b56eadff6b0f668c3b26b4b1aeb308a1fcc1c680d329a6705025f1c98a0b5e5bfcb163caa";

fn ecdh(c: &mut Criterion) {
    let sk_bytes = hex::decode(SK).unwrap();
    let pk_bytes = hex::decode(PK).unwrap();

    c.bench_function("P-384 ECDH", |b| {
        b.iter(|| {
            core::hint::black_box(
                libcrux_p384::derive_ecdh(
                    core::hint::black_box(&sk_bytes),
                    core::hint::black_box(&pk_bytes),
                )
                .unwrap(),
            )
        })
    });
}

criterion_group!(benches, ecdh);
criterion_main!(benches);
