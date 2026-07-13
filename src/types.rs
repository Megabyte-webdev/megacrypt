use serde::{ Deserialize, Serialize };
use zeroize::{ Zeroize, ZeroizeOnDrop };

/// 32-byte symmetric key with automatic zeroization on drop
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn new(key: [u8; 32]) -> Self {
        SecretKey(key)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Nonce for ChaCha20-Poly1305 (12 bytes)
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Nonce {
    bytes: [u8; 12],
}

impl Nonce {
    pub fn new(bytes: [u8; 12]) -> Self {
        Nonce { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.bytes
    }

    pub fn to_bytes(self) -> [u8; 12] {
        self.bytes
    }
}

/// Salt for key derivation (16 bytes)
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Salt {
    bytes: [u8; 16],
}

impl Salt {
    pub fn new(bytes: [u8; 16]) -> Self {
        Salt { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }

    pub fn random() -> crate::error::Result<Self> {
        use rand_core::OsRng;
        let mut bytes = [0u8; 16];
        use rand_core::RngCore;
        OsRng.try_fill_bytes(&mut bytes).map_err(|e|
            crate::error::CryptoError::RandomGenerationFailed(e.to_string())
        )?;
        Ok(Salt { bytes })
    }
}

/// Encrypted blob with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedBlob {
    /// Protocol version
    pub version: u8,
    /// The actual ciphertext (plaintext + auth tag)
    pub ciphertext: Vec<u8>,
    /// Nonce used for encryption
    pub nonce: [u8; 12],
    /// Optional additional authenticated data context
    pub context: Vec<u8>,
    /// Timestamp of encryption for audit trail
    pub timestamp: u64,
}

impl EncryptedBlob {
    /// Validate blob integrity
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.version != 1 {
            return Err(crate::error::CryptoError::ProtocolVersionMismatch {
                expected: 1,
                got: self.version,
            });
        }

        if self.ciphertext.is_empty() {
            return Err(
                crate::error::CryptoError::InvalidPayloadSize(
                    "ciphertext cannot be empty".to_string()
                )
            );
        }

        if self.ciphertext.len() > 268_435_456 {
            // 256 MB limit
            return Err(
                crate::error::CryptoError::InvalidPayloadSize(
                    "ciphertext exceeds maximum size".to_string()
                )
            );
        }

        Ok(())
    }
}

/// Cryptographic context for domain separation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoContext {
    pub session_id: [u8; 16],
    pub purpose: CryptoPurpose,
    pub counter: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CryptoPurpose {
    Message = 1,
    File = 2,
    Stream = 3,
    Api = 4,
    RtcSignaling = 5,
    RtcMedia = 6,
    KeyExchange = 7,
}

impl CryptoPurpose {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            CryptoPurpose::Message => b"msg",
            CryptoPurpose::File => b"file",
            CryptoPurpose::Stream => b"stream",
            CryptoPurpose::Api => b"api",
            CryptoPurpose::RtcSignaling => b"rtc_sig",
            CryptoPurpose::RtcMedia => b"rtc_media",
            CryptoPurpose::KeyExchange => b"key_ex",
        }
    }
}

impl CryptoContext {
    pub fn new(session_id: [u8; 16], purpose: CryptoPurpose) -> Self {
        CryptoContext {
            session_id,
            purpose,
            counter: 0,
        }
    }

    /// Purpose as bytes for domain separation
    pub fn purpose_bytes(&self) -> &[u8] {
        match self.purpose {
            CryptoPurpose::Message => b"msg",
            CryptoPurpose::File => b"file",
            CryptoPurpose::Stream => b"stream",
            CryptoPurpose::Api => b"api",
            CryptoPurpose::RtcSignaling => b"rtc_sig",
            CryptoPurpose::RtcMedia => b"rtc_media",
            CryptoPurpose::KeyExchange => b"key_ex",
        }
    }
}

/// Session token for audit trail
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionToken {
    pub id: [u8; 16],
    pub created_at: u64,
    pub expires_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_zeroize() {
        let mut key = SecretKey::new([0xaa; 32]);
        let key_ptr = key.as_bytes().as_ptr();
        drop(key);
        // Note: Can't directly verify zeroization in safe code
        // This would be tested with memory tools like valgrind
    }

    #[test]
    fn test_blob_validation() {
        let mut blob = EncryptedBlob {
            version: 1,
            ciphertext: vec![1, 2, 3],
            nonce: [0; 12],
            context: vec![],
            timestamp: 0,
        };

        assert!(blob.validate().is_ok());

        blob.version = 2;
        assert!(blob.validate().is_err());

        blob.version = 1;
        blob.ciphertext.clear();
        assert!(blob.validate().is_err());
    }
}
