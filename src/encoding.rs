use base64::{ engine::general_purpose, Engine as _ };

use crate::types::EncryptedBlob;

/// Rust blob -> Base64 string
pub fn encode_blob(blob: &EncryptedBlob) -> String {
    let bytes = bincode::serialize(blob).unwrap();
    general_purpose::STANDARD.encode(bytes)
}

/// Base64 string -> Rust blob
pub fn decode_blob(data: &str) -> EncryptedBlob {
    let bytes = general_purpose::STANDARD.decode(data).unwrap();
    bincode::deserialize(&bytes).unwrap()
}
