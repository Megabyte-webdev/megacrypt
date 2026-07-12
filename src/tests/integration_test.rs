use crate::{
    engine::CryptoEngine,
    kdf::{ KdfParams, derive_password_key },
    types::{ CryptoPurpose, Salt },
};

// Salt must be exactly 16 bytes to match your domain types
const RAW_SALT: [u8; 16] = *b"megacryptsalt16b";

#[test]
fn test_text_encryption() {
    let salt = Salt::new(RAW_SALT);
    let key = derive_password_key(b"password", &salt, KdfParams::default()).unwrap();
    let engine = CryptoEngine::new(key);

    let msg = b"hello world secure";

    let enc = engine.encrypt_message(msg, CryptoPurpose::Message).unwrap();
    let dec = engine.decrypt_message(&enc, CryptoPurpose::Message).unwrap();

    assert_eq!(msg.to_vec(), dec);
}

#[test]
fn test_stream_encryption() {
    let salt = Salt::new(RAW_SALT);
    let key = derive_password_key(b"password", &salt, KdfParams::default()).unwrap();
    let engine = CryptoEngine::new(key);

    let c1 = engine.encrypt_message(b"frame-1", CryptoPurpose::Stream).unwrap();
    let c2 = engine.encrypt_message(b"frame-2", CryptoPurpose::Stream).unwrap();

    let d1 = engine.decrypt_message(&c1, CryptoPurpose::Stream).unwrap();
    let d2 = engine.decrypt_message(&c2, CryptoPurpose::Stream).unwrap();

    assert_eq!(d1, b"frame-1");
    assert_eq!(d2, b"frame-2");
}

#[test]
fn test_api_encryption() {
    let salt = Salt::new(RAW_SALT);
    let key = derive_password_key(b"password", &salt, KdfParams::default()).unwrap();
    let engine = CryptoEngine::new(key);

    let req = engine.encrypt_message(b"{\"ping\":1}", CryptoPurpose::Api).unwrap();
    let res = engine.decrypt_message(&req, CryptoPurpose::Api).unwrap();

    assert_eq!(res, b"{\"ping\":1}");
}

#[test]
fn test_tamper_detection() {
    let salt = Salt::new(RAW_SALT);
    let key = derive_password_key(b"password", &salt, KdfParams::default()).unwrap();
    let engine = CryptoEngine::new(key);

    let mut enc = engine.encrypt_message(b"important data", CryptoPurpose::Message).unwrap();

    // simulate tampering
    if let Some(byte) = enc.ciphertext.get_mut(0) {
        *byte ^= 0xaa;
    }

    let result = engine.decrypt_message(&enc, CryptoPurpose::Message);

    // CryptoEngine returns a Result, so tampering triggers an Err
    assert!(result.is_err());
}

#[test]
fn test_kdf_consistency() {
    let salt = Salt::new(RAW_SALT);
    let k1 = derive_password_key(b"same-password", &salt, KdfParams::default()).unwrap();
    let k2 = derive_password_key(b"same-password", &salt, KdfParams::default()).unwrap();

    assert_eq!(k1.as_bytes(), k2.as_bytes());
}

#[test]
fn test_domain_isolation() {
    let salt = Salt::new(RAW_SALT);
    let key = derive_password_key(b"password", &salt, KdfParams::default()).unwrap();
    let engine = CryptoEngine::new(key);

    let enc = engine.encrypt_message(b"data", CryptoPurpose::Message).unwrap();

    // Decrypting with the wrong purpose context should error out
    let wrong = engine.decrypt_message(&enc, CryptoPurpose::File);

    assert!(wrong.is_err());
}
