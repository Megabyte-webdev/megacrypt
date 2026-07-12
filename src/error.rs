use serde::{ Deserialize };
use thiserror::Error;

#[derive(Error, Deserialize, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")] EncryptionFailed(String),

    #[error("Decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    #[error("Invalid key: {0}")] InvalidKey(String),

    #[error("Invalid nonce: expected 12 bytes")]
    InvalidNonce,

    #[error("Invalid salt: expected 16 bytes")]
    InvalidSalt,

    #[error("Serialization error: {0}")] SerializationError(String),

    #[error("Deserialization error: {0}")] DeserializationError(String),

    #[error("Key derivation failed: {0}")] KeyDerivationFailed(String),

    #[error("Random number generation failed: {0}")] RandomGenerationFailed(String),

    #[error("Session error: {0}")] SessionError(String),

    #[error("Nonce reuse detected - potential security issue")]
    NonceReuse,

    #[error("Key rotation failed: {0}")] KeyRotationFailed(String),

    #[error("Invalid UTF-8: {0}")] InvalidUtf8(String),

    #[error("File operation failed: {0}")] FileOperationFailed(String),

    #[error("Encoding error: {0}")] EncodingError(String),

    #[error("Protocol version mismatch: expected {expected}, got {got}")] ProtocolVersionMismatch {
        expected: u8,
        got: u8,
    },

    #[error("Invalid payload size: {0}")] InvalidPayloadSize(String),

    #[error("Insufficient data: {0}")] InsufficientData(String),
}

impl From<std::string::FromUtf8Error> for CryptoError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        CryptoError::InvalidUtf8(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CryptoError>;
