use argon2::{
    password_hash::{ PasswordHasher, SaltString },
    Algorithm,
    Argon2,
    Params,
    PasswordHash,
    PasswordVerifier,
    Version,
};
use blake3::Hasher;
use crate::error::{ CryptoError, Result };
use crate::types::{ SecretKey, Salt };

/// KDF parameters for Argon2
/// These are conservative settings suitable for password-to-key derivation
#[derive(Clone, Debug)] // Added Clone and Debug here
pub struct KdfParams {
    /// Memory size in KiB (128 MiB default)
    pub memory_cost: u32,
    /// Number of iterations
    pub time_cost: u32,
    /// Degree of parallelism
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            memory_cost: 131_072, // 128 MiB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

impl KdfParams {
    pub fn fast() -> Self {
        KdfParams {
            memory_cost: 19_456, // 19 MiB
            time_cost: 2,
            parallelism: 1,
        }
    }

    pub fn high_security() -> Self {
        KdfParams {
            memory_cost: 262_144, // 256 MiB
            time_cost: 4,
            parallelism: 8,
        }
    }
}

/// Derive a 32-byte key from a password using Argon2id
pub fn derive_password_key(password: &[u8], salt: &Salt, params: KdfParams) -> Result<SecretKey> {
    if password.is_empty() {
        return Err(CryptoError::KeyDerivationFailed("password cannot be empty".to_string()));
    }

    let params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(32)
    ).map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let password_str = String::from_utf8(password.to_vec()).unwrap_or_else(|_|
        String::from_utf8_lossy(password).to_string()
    );

    let salt_string = SaltString::encode_b64(salt.as_bytes()).map_err(|e|
        CryptoError::KeyDerivationFailed(e.to_string())
    )?;

    // Changed Version::V1_3 to Version::V0x13
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password_str.as_bytes(), &salt_string)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let hash_bytes = password_hash.hash.ok_or_else(||
        CryptoError::KeyDerivationFailed("no hash produced".to_string())
    )?;

    let mut key = [0u8; 32];
    let hash_vec = hash_bytes.as_bytes();

    if hash_vec.len() < 32 {
        return Err(CryptoError::KeyDerivationFailed("derived key too short".to_string()));
    }

    key.copy_from_slice(&hash_vec[..32]);
    Ok(SecretKey::new(key))
}

pub fn derive_context_key(master_key: &SecretKey, context: &[u8]) -> Result<SecretKey> {
    let mut hasher = Hasher::new();

    hasher.update(master_key.as_bytes());
    hasher.update(context);
    hasher.update(b"megacrypt-context-v1");

    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());

    Ok(SecretKey::new(key))
}

pub fn derive_multiple_keys(master_key: &SecretKey, contexts: &[&[u8]]) -> Result<Vec<SecretKey>> {
    contexts
        .iter()
        .map(|ctx| derive_context_key(master_key, ctx))
        .collect()
}

pub fn verify_password(password: &[u8], password_hash: &str) -> Result<bool> {
    let hash = PasswordHash::new(password_hash).map_err(|e|
        CryptoError::KeyDerivationFailed(e.to_string())
    )?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password, &hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_password_key() {
        let password = b"test-password-123";
        let salt = Salt::random().unwrap();
        let params = KdfParams::fast();

        let key1 = derive_password_key(password, &salt, params.clone()).unwrap();
        let key2 = derive_password_key(password, &salt, params.clone()).unwrap();

        // Same input should produce same key
        assert_eq!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_derive_context_key() {
        let master = SecretKey::new([0xaa; 32]);
        let ctx1 = b"context-1";
        let ctx2 = b"context-2";

        let key1 = derive_context_key(&master, ctx1).unwrap();
        let key2 = derive_context_key(&master, ctx2).unwrap();

        // Different contexts should produce different keys
        assert_ne!(key1.as_bytes(), key2.as_bytes());

        // Same context should produce same key
        let key1_repeat = derive_context_key(&master, ctx1).unwrap();
        assert_eq!(key1.as_bytes(), key1_repeat.as_bytes());
    }

    #[test]
    fn test_empty_password_fails() {
        let salt = Salt::random().unwrap();
        let result = derive_password_key(b"", &salt, KdfParams::default());
        assert!(result.is_err());
    }
}
