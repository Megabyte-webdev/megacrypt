use crate::{ kdf::derive_context_key, types::SecretKey };

pub struct Session {
    master_key: [u8; 32],
}

impl Session {
    pub fn new(master_key: [u8; 32]) -> Self {
        Self { master_key }
    }

    /// Derive per-purpose key (VERY IMPORTANT)
    pub fn derive_context_key(&self, context: &[u8]) -> [u8; 32] {
        let master_secret_key = SecretKey::new(self.master_key);
        derive_context_key(&master_secret_key, context)
            .map(|secret_key| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(secret_key.as_bytes());
                bytes
            })
            .unwrap_or([0u8; 32])
    }
}
