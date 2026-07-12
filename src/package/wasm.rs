use wasm_bindgen::prelude::*;
use crate::derive_password_key;
use crate::engine::CryptoEngine;
use crate::kdf::KdfParams;
use crate::api::ApiCrypto;
use crate::protocol::CryptoPacket;
use crate::types::Salt;

#[wasm_bindgen]
pub struct JSEngine {
    engine: CryptoEngine,
}

#[wasm_bindgen]
impl JSEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(password: &[u8], salt_bytes: &[u8]) -> Result<JSEngine, JsValue> {
        let mut fixed_salt = [0u8; 16];
        if salt_bytes.len() != 16 {
            return Err(JsValue::from_str("Salt must be exactly 16 bytes"));
        }
        fixed_salt.copy_from_slice(salt_bytes);

        let salt = Salt::new(fixed_salt);
        let key = derive_password_key(password, &salt, KdfParams::default()).map_err(|e|
            JsValue::from_str(&e.to_string())
        )?;

        Ok(JSEngine { engine: CryptoEngine::new(key) })
    }

    pub fn encrypt_req(&self, plain_data: &[u8]) -> String {
        let packet = ApiCrypto::encrypt_request(&self.engine, plain_data);
        // Serialize the CryptoPacket to a JSON string for JS
        serde_json::to_string(&packet).unwrap()
    }

    pub fn decrypt_req(&self, json_packet: &str) -> Vec<u8> {
        let packet: CryptoPacket = serde_json::from_str(json_packet).unwrap();
        ApiCrypto::decrypt_request(&self.engine, packet)
    }
}
