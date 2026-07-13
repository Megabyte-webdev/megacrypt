use std::collections::HashMap;
use rand_core::{ OsRng, RngCore };

use crate::{ CryptoEngine, derive_password_key, kdf::KdfParams, types::Salt };

fn entropy(data: &[u8]) -> f64 {
    let mut counts = HashMap::new();

    for byte in data {
        *counts.entry(*byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;

    counts
        .values()
        .map(|count| {
            let p = (*count as f64) / len;
            -p * p.log2()
        })
        .sum()
}

#[test]
fn test_ciphertext_entropy() {
    let salt = Salt::new(*b"megacryptsalt16b");

    let key = derive_password_key(b"password", &salt, KdfParams::default()).unwrap();

    let engine = CryptoEngine::new(key);

    let mut plaintext = vec![0u8; 1024];

    OsRng.fill_bytes(&mut plaintext);

    let blob = engine.encrypt_api(&plaintext).unwrap();

    let result = entropy(&blob.ciphertext);

    println!("Cipher entropy: {}", result);

    assert!(result > 7.5, "Entropy too low");
}
