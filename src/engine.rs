use crate::aead::{ decrypt, encrypt, NonceManager };
use crate::error::Result;
use crate::kdf::{ derive_context_key };
use crate::types::{ CryptoPurpose, EncryptedBlob, SecretKey };
use chrono::Utc;
use std::sync::{ Arc, Mutex };

/// Main cryptographic engine for the SDK
/// Handles all encryption/decryption operations with session management
pub struct CryptoEngine {
    master_key: SecretKey,
    nonce_manager: Arc<NonceManager>,
    session_id: [u8; 16],
    created_at: i64,
    audit_log: Arc<Mutex<Vec<AuditEntry>>>,
}

#[derive(Clone, Debug)]
pub struct AuditEntry {
    pub timestamp: i64,
    pub operation: String,
    pub context: String,
    pub success: bool,
}

impl CryptoEngine {
    /// Create a new crypto engine with a master key
    pub fn new(master_key: SecretKey) -> Self {
        use rand_core::{ OsRng, RngCore };
        let mut session_id = [0u8; 16];
        OsRng.fill_bytes(&mut session_id);

        CryptoEngine {
            master_key,
            nonce_manager: Arc::new(NonceManager::new()),
            session_id,
            created_at: Utc::now().timestamp(),
            audit_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Encrypt a message with domain separation
    pub fn encrypt_message(
        &self,
        plaintext: &[u8],
        purpose: CryptoPurpose
    ) -> Result<EncryptedBlob> {
        let context_key = derive_context_key(&self.master_key, purpose.as_bytes())?;
        let mut aad = Vec::new();
        aad.extend_from_slice(&self.session_id);
        aad.extend_from_slice(purpose.as_bytes());

        let blob = encrypt(&context_key, plaintext, &aad, &self.nonce_manager)?;

        self.log_audit("encrypt", &format!("{:?}", purpose), true);
        Ok(blob)
    }

    /// Decrypt a message with verification
    pub fn decrypt_message(&self, blob: &EncryptedBlob, purpose: CryptoPurpose) -> Result<Vec<u8>> {
        let context_key = derive_context_key(&self.master_key, purpose.as_bytes())?;
        let mut aad = Vec::new();
        aad.extend_from_slice(&self.session_id);
        aad.extend_from_slice(purpose.as_bytes());

        let plaintext = decrypt(&context_key, blob, &aad)?;

        self.log_audit("decrypt", &format!("{:?}", purpose), true);
        Ok(plaintext)
    }

    /// High-level API for real-time signaling (WebRTC)
    pub fn encrypt_signaling(&self, data: &[u8]) -> Result<EncryptedBlob> {
        self.encrypt_message(data, CryptoPurpose::RtcSignaling)
    }

    pub fn decrypt_signaling(&self, blob: &EncryptedBlob) -> Result<Vec<u8>> {
        self.decrypt_message(blob, CryptoPurpose::RtcSignaling)
    }

    /// High-level API for media streams (actual video/audio in WebRTC)
    pub fn encrypt_media(&self, data: &[u8]) -> Result<EncryptedBlob> {
        self.encrypt_message(data, CryptoPurpose::RtcMedia)
    }

    pub fn decrypt_media(&self, blob: &EncryptedBlob) -> Result<Vec<u8>> {
        self.decrypt_message(blob, CryptoPurpose::RtcMedia)
    }

    /// Generic message encryption
    pub fn encrypt_api(&self, data: &[u8]) -> Result<EncryptedBlob> {
        self.encrypt_message(data, CryptoPurpose::Api)
    }

    pub fn decrypt_api(&self, blob: &EncryptedBlob) -> Result<Vec<u8>> {
        self.decrypt_message(blob, CryptoPurpose::Api)
    }

    /// File encryption
    pub fn encrypt_file(&self, data: &[u8]) -> Result<EncryptedBlob> {
        self.encrypt_message(data, CryptoPurpose::File)
    }

    pub fn decrypt_file(&self, blob: &EncryptedBlob) -> Result<Vec<u8>> {
        self.decrypt_message(blob, CryptoPurpose::File)
    }

    /// Streaming data (for chunked operations)
    pub fn encrypt_stream_chunk(&self, chunk: &[u8]) -> Result<EncryptedBlob> {
        self.encrypt_message(chunk, CryptoPurpose::Stream)
    }

    pub fn decrypt_stream_chunk(&self, blob: &EncryptedBlob) -> Result<Vec<u8>> {
        self.decrypt_message(blob, CryptoPurpose::Stream)
    }

    /// Internal audit logging
    fn log_audit(&self, operation: &str, context: &str, success: bool) {
        if let Ok(mut log) = self.audit_log.lock() {
            log.push(AuditEntry {
                timestamp: Utc::now().timestamp(),
                operation: operation.to_string(),
                context: context.to_string(),
                success,
            });
        }
    }

    /// Get audit log (for compliance/debugging)
    pub fn audit_log(&self) -> Result<Vec<AuditEntry>> {
        self.audit_log
            .lock()
            .map(|log| log.clone())
            .map_err(|_| crate::error::CryptoError::SessionError("audit log poisoned".to_string()))
    }

    /// Clear audit log (use with caution)
    pub fn clear_audit_log(&self) -> Result<()> {
        self.audit_log
            .lock()
            .map_err(|_| crate::error::CryptoError::SessionError("audit log poisoned".to_string()))?
            .clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let key = SecretKey::new([0xaa; 32]);
        let engine = CryptoEngine::new(key);
        assert!(!engine.session_id().is_empty());
    }

    #[test]
    fn test_encrypt_decrypt_cycle() {
        let key = SecretKey::new([0xbb; 32]);
        let engine = CryptoEngine::new(key);

        let plaintext = b"sensitive data";
        let blob = engine.encrypt_api(plaintext).unwrap();
        let decrypted = engine.decrypt_api(&blob).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_domain_separation() {
        let key = SecretKey::new([0xcc; 32]);
        let engine = CryptoEngine::new(key);

        let plaintext = b"test";
        let api_blob = engine.encrypt_api(plaintext).unwrap();

        // Trying to decrypt as media should fail (wrong context)
        assert!(engine.decrypt_media(&api_blob).is_err());
    }

    #[test]
    fn test_audit_logging() {
        let key = SecretKey::new([0xdd; 32]);
        let engine = CryptoEngine::new(key);

        let _ = engine.encrypt_api(b"test").unwrap();
        let _ = engine.decrypt_api(&engine.encrypt_api(b"test").unwrap()).unwrap();

        let log = engine.audit_log().unwrap();
        assert!(log.len() >= 2); // At least encrypt and decrypt
    }
}
