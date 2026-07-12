use megacrypt::{ CryptoEngine, derive_password_key };
use megacrypt::api::ApiCrypto;
use megacrypt::types::Salt;
use megacrypt::kdf::KdfParams;

fn main() {
    // 1. Create a valid 16-byte salt type
    let salt = Salt::new(*b"megacryptsalt16b");

    // 2. Supply the missing KdfParams argument (using default parameters)
    //    and unwrap the Result
    let key = derive_password_key(b"password", &salt, KdfParams::default()).expect(
        "Failed to derive password key"
    );

    let engine = CryptoEngine::new(key);

    // 3. Encrypt and wrap using the API layer
    let packet = ApiCrypto::encrypt_request(&engine, b"afo@secure");

    // This is what you send to frontend / API
    println!("WEB RESPONSE: {}", packet.data);

    // 4. Decrypt back
    let decrypted = ApiCrypto::decrypt_request(&engine, packet);

    println!("DECRYPTED: {}", String::from_utf8_lossy(&decrypted));
}
