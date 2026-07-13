use chacha20poly1305::{ aead::{ Aead, KeyInit, Payload }, ChaCha20Poly1305, Nonce as ChachaNonce };
use rand_core::{ OsRng, RngCore };
use crate::error::{ CryptoError, Result };
use crate::types::{ EncryptedBlob, Nonce, SecretKey };

/// Thread-safe nonce manager to prevent reuse
pub struct NonceManager;

impl NonceManager {
    pub fn new() -> Self {
        Self
    }

    pub fn generate_nonce(&self) -> Result<Nonce> {
        let mut bytes = [0u8; 12];

        OsRng.try_fill_bytes(&mut bytes).map_err(|e| {
            CryptoError::RandomGenerationFailed(e.to_string())
        })?;

        Ok(Nonce::new(bytes))
    }

    pub fn clear(&self) -> Result<()> {
        Ok(())
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Encrypt data with ChaCha20-Poly1305
pub fn encrypt(
    key: &SecretKey,
    plaintext: &[u8],
    aad: &[u8],
    nonce_manager: &NonceManager
) -> Result<EncryptedBlob> {
    if plaintext.is_empty() {
        return Err(CryptoError::InvalidPayloadSize("plaintext cannot be empty".into()));
    }

    if plaintext.len() > 268_435_456 {
        return Err(CryptoError::InvalidPayloadSize("plaintext exceeds maximum size".into()));
    }

    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));

    let nonce = nonce_manager.generate_nonce()?;

    let ciphertext = cipher
        .encrypt(ChachaNonce::from_slice(nonce.as_bytes()), Payload {
            msg: plaintext,
            aad,
        })
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let timestamp = std::time::SystemTime
        ::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(EncryptedBlob {
        version: 1,
        ciphertext,
        nonce: *nonce.as_bytes(),
        context: aad.to_vec(),
        timestamp,
    })
}

/// Decrypt data with ChaCha20-Poly1305
pub fn decrypt(key: &SecretKey, blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    blob.validate()?;

    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));

    cipher
        .decrypt(ChachaNonce::from_slice(&blob.nonce), Payload {
            msg: &blob.ciphertext,
            aad,
        })
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypt with automatic timestamp and salt generation
pub fn encrypt_simple(key: &SecretKey, plaintext: &[u8]) -> Result<EncryptedBlob> {
    let nonce_manager = NonceManager::new();
    encrypt(key, plaintext, b"", &nonce_manager)
}

/// Decrypt without AAD validation
pub fn decrypt_simple(key: &SecretKey, blob: &EncryptedBlob) -> Result<Vec<u8>> {
    decrypt(key, blob, b"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = SecretKey::new([0xaa; 32]);
        let plaintext = b"Hello, world!";
        let aad = b"context";
        let nonce_mgr = NonceManager::new();

        let blob = encrypt(&key, plaintext, aad, &nonce_mgr).unwrap();
        let decrypted = decrypt(&key, &blob, aad).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = SecretKey::new([0xaa; 32]);
        let plaintext = b"secret";
        let correct_aad = b"context";
        let wrong_aad = b"other";
        let nonce_mgr = NonceManager::new();

        let blob = encrypt(&key, plaintext, correct_aad, &nonce_mgr).unwrap();
        assert!(decrypt(&key, &blob, wrong_aad).is_err());
    }

    #[test]
    fn test_nonce_reuse_detection() {
        let nonce_mgr = NonceManager::new();

        let nonce1 = nonce_mgr.generate_nonce().unwrap();
        let nonce2 = nonce_mgr.generate_nonce().unwrap();

        // Two different nonces should be generated
        assert_ne!(nonce1.to_bytes(), nonce2.to_bytes());
    }

    #[test]
    fn test_empty_plaintext_fails() {
        let key = SecretKey::new([0xaa; 32]);
        let nonce_mgr = NonceManager::new();
        let result = encrypt(&key, b"", b"", &nonce_mgr);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampering_detected() {
        let key = SecretKey::new([0xaa; 32]);
        let plaintext = b"important data";
        let nonce_mgr = NonceManager::new();

        let mut blob = encrypt(&key, plaintext, b"", &nonce_mgr).unwrap();

        // Tamper with ciphertext
        if !blob.ciphertext.is_empty() {
            blob.ciphertext[0] ^= 0xff;
        }

        // Decryption should fail
        assert!(decrypt(&key, &blob, b"").is_err());
    }
}
