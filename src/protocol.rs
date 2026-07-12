use crate::types::EncryptedBlob;
use crate::error::{ CryptoError, Result };
use serde::{ Deserialize, Serialize };
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

/// Wire format for transmitting encrypted data
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoPacket {
    /// Protocol version
    pub version: u8,
    /// Base64-encoded encrypted blob
    pub data: String,
    /// Optional metadata (e.g., sender ID, timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<PacketMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketMetadata {
    pub sender: Option<String>,
    pub recipient: Option<String>,
    pub timestamp: u64,
}

impl CryptoPacket {
    /// Create packet from encrypted blob
    pub fn from_blob(blob: &EncryptedBlob) -> Result<Self> {
        let bytes = bincode
            ::serialize(blob)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
        let data = BASE64.encode(&bytes);

        Ok(CryptoPacket {
            version: 1,
            data,
            metadata: None,
        })
    }

    /// Extract encrypted blob from packet
    pub fn to_blob(&self) -> Result<EncryptedBlob> {
        if self.version != 1 {
            return Err(CryptoError::ProtocolVersionMismatch {
                expected: 1,
                got: self.version,
            });
        }

        let bytes = BASE64.decode(&self.data).map_err(|e|
            CryptoError::EncodingError(e.to_string())
        )?;

        bincode::deserialize(&bytes).map_err(|e| CryptoError::DeserializationError(e.to_string()))
    }

    /// Convert to JSON (for HTTP APIs)
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| CryptoError::EncodingError(e.to_string()))
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json
            ::from_str(json)
            .map_err(|e| CryptoError::EncodingError(format!("JSON decode: {}", e)))
    }

    /// Serialize to bincode (for network transmission)
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| CryptoError::SerializationError(e.to_string()))
    }

    /// Parse from bincode
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| CryptoError::DeserializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EncryptedBlob;

    #[test]
    fn test_packet_round_trip() {
        let blob = EncryptedBlob {
            version: 1,
            ciphertext: vec![1, 2, 3, 4, 5],
            nonce: [0; 12],
            salt: [0; 16],
            context: vec![],
            timestamp: 1234567890,
        };

        let packet = CryptoPacket::from_blob(&blob).unwrap();
        let recovered = packet.to_blob().unwrap();

        assert_eq!(blob.ciphertext, recovered.ciphertext);
        assert_eq!(blob.nonce, recovered.nonce);
    }

    #[test]
    fn test_json_serialization() {
        let blob = EncryptedBlob {
            version: 1,
            ciphertext: vec![0xaa, 0xbb],
            nonce: [0; 12],
            salt: [0; 16],
            context: b"test".to_vec(),
            timestamp: 999,
        };

        let packet = CryptoPacket::from_blob(&blob).unwrap();
        let json = packet.to_json().unwrap();
        let recovered = CryptoPacket::from_json(&json).unwrap();

        assert_eq!(packet.version, recovered.version);
    }
}
