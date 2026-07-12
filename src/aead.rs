use chacha20poly1305::{ aead::{ Aead, KeyInit, Payload }, ChaCha20Poly1305, Nonce as ChachaNonce };
use rand_core::{ OsRng, RngCore };
use std::collections::HashSet;
use std::sync::Mutex;
use crate::error::{ CryptoError, Result };
use crate::types::{ EncryptedBlob, Nonce, SecretKey, Salt };

/// Thread-safe nonce manager to prevent reuse
pub struct NonceManager {
    used_nonces: Mutex<HashSet<[u8; 12]>>,
}

impl NonceManager {
    pub fn new() -> Self {
        NonceManager {
            used_nonces: Mutex::new(HashSet::new()),
        }
    }

    /// Generate a random nonce and track it
    pub fn generate_nonce(&self) -> Result<Nonce> {
        let mut bytes = [0u8; 12];
        OsRng.try_fill_bytes(&mut bytes).map_err(|e|
            CryptoError::RandomGenerationFailed(e.to_string())
        )?;

        let mut used = self.used_nonces
            .lock()
            .map_err(|_| CryptoError::RandomGenerationFailed("mutex poisoned".to_string()))?;

        // Check for collision (extremely unlikely with 12 random bytes, but cryptography requires certainty)
        if used.contains(&bytes) {
            return Err(CryptoError::NonceReuse);
        }

        used.insert(bytes);

        Ok(Nonce::new(bytes))
    }

    /// Clear the nonce cache (use with caution - only when you're sure keys won't be reused)
    pub fn clear(&self) -> Result<()> {
        self.used_nonces
            .lock()
            .map_err(|_| CryptoError::RandomGenerationFailed("mutex poisoned".to_string()))?
            .clear();
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
        return Err(CryptoError::InvalidPayloadSize("plaintext cannot be empty".to_string()));
    }

    if plaintext.len() > 268_435_456 {
        // 256 MB limit
        return Err(CryptoError::InvalidPayloadSize("plaintext exceeds maximum size".to_string()));
    }

    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    let nonce = nonce_manager.generate_nonce()?;
    let chacha_nonce = ChachaNonce::from_slice(nonce.as_bytes());

    let ciphertext = cipher
        .encrypt(chacha_nonce, Payload {
            msg: plaintext,
            aad,
        })
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let salt = Salt::random()?;
    let timestamp = std::time::SystemTime
        ::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(EncryptedBlob {
        version: 1,
        ciphertext,
        nonce: *nonce.as_bytes(),
        salt: *salt.as_bytes(),
        context: aad.to_vec(),
        timestamp,
    })
}

/// Decrypt data with ChaCha20-Poly1305
pub fn decrypt(key: &SecretKey, blob: &EncryptedBlob, aad: &[u8]) -> Result<Vec<u8>> {
    // Validate blob before processing
    blob.validate()?;

    // Verify context matches
    if blob.context != aad {
        return Err(CryptoError::DecryptionFailed);
    }

    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    let chacha_nonce = ChachaNonce::from_slice(&blob.nonce);

    cipher
        .decrypt(chacha_nonce, Payload {
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
