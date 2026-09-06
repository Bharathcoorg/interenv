use criterion::{criterion_group, criterion_main, Criterion};
use interenv::crypto::cipher::{decrypt_payload, encrypt_payload, CIPHER_XCHACHA20_POLY1305};
use interenv::crypto::kdf::derive_key_from_passphrase;

fn bench_encrypt(c: &mut Criterion) {
    let key = [42u8; 32];
    let plaintext = vec![0xABu8; 4096];
    c.bench_function("encrypt_4KiB", |b| {
        b.iter(|| encrypt_payload(&plaintext, &key).unwrap());
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let key = [42u8; 32];
    let plaintext = vec![0xABu8; 4096];
    let enc = encrypt_payload(&plaintext, &key).unwrap();
    c.bench_function("decrypt_4KiB", |b| {
        b.iter(|| decrypt_payload(&enc, &key, CIPHER_XCHACHA20_POLY1305).unwrap());
    });
}

fn bench_kdf(c: &mut Criterion) {
    let salt = [0u8; 16];
    c.bench_function("argon2id_derive", |b| {
        b.iter(|| derive_key_from_passphrase("correct horse battery staple", &salt).unwrap());
    });
}

criterion_group!(benches, bench_encrypt, bench_decrypt, bench_kdf);
criterion_main!(benches);
