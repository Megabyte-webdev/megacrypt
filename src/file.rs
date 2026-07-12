use std::fs;

use crate::{ engine::CryptoEngine, types::{ CryptoPurpose, EncryptedBlob } };

pub struct FileCrypto;

impl FileCrypto {
    pub fn encrypt_file(engine: &CryptoEngine, input: &str, output: &str) -> Result<(), String> {
        let data = fs::read(input).map_err(|e| e.to_string())?;

        let enc = engine.encrypt_message(&data, CryptoPurpose::File).unwrap();

        let encoded = bincode::serialize(&enc).map_err(|e| e.to_string())?;

        fs::write(output, encoded).map_err(|e| e.to_string())?;

        Ok(())
    }

    pub fn decrypt_file(engine: &CryptoEngine, input: &str, output: &str) -> Result<(), String> {
        let data = fs::read(input).map_err(|e| e.to_string())?;

        let blob: EncryptedBlob = bincode::deserialize(&data).map_err(|e| e.to_string())?;

        let dec = engine
            .decrypt_message(&blob, CryptoPurpose::File)
            .map_err(|_| "decryption failed")?;

        fs::write(output, dec).map_err(|e| e.to_string())?;

        Ok(())
    }
}
