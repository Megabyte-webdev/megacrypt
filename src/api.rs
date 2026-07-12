use crate::{
    encoding::{ decode_blob, encode_blob },
    engine::CryptoEngine,
    protocol::CryptoPacket,
    types::CryptoPurpose,
};

pub struct ApiCrypto;

impl ApiCrypto {
    /// Encrypt → Web-safe packet
    pub fn encrypt_request(engine: &CryptoEngine, data: &[u8]) -> CryptoPacket {
        let blob = engine.encrypt_message(data, CryptoPurpose::Api).unwrap();

        CryptoPacket {
            version: 1,
            data: encode_blob(&blob),
            metadata: None,
        }
    }

    /// Decrypt → original data
    pub fn decrypt_request(engine: &CryptoEngine, packet: CryptoPacket) -> Vec<u8> {
        let blob = decode_blob(&packet.data);

        engine.decrypt_message(&blob, CryptoPurpose::Api).unwrap()
    }
}
