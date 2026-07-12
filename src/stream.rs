use crate::engine::CryptoEngine;
use crate::types::{ EncryptedBlob, CryptoPurpose::Stream };

pub struct StreamCrypto;

impl StreamCrypto {
    pub fn encrypt_chunk(engine: &CryptoEngine, chunk: &[u8]) -> EncryptedBlob {
        let result = engine.encrypt_message(chunk, Stream);
        result.unwrap()
    }

    pub fn decrypt_chunk(engine: &CryptoEngine, blob: &EncryptedBlob) -> Vec<u8> {
        engine.decrypt_message(blob, Stream).unwrap()
    }
}
