# MegaCrypt SDK

[![Crates.io](https://img.shields.io/crates/v/megacrypt.svg?style=flat-square)](https://crates.io/crates/megacrypt)
[![npm](https://img.shields.io/npm/v/megacrypt.svg?style=flat-square)](https://www.npmjs.com/package/megacrypt)
[![CI](https://img.shields.io/github/actions/workflow/status/Megabyte-webdev/megacrypt/release.yml?style=flat-square)](https://github.com/Megabyte-webdev/megacrypt/actions)
[![License](https://img.shields.io/badge/license-MIT%20%7C%20Apache--2.0-blue.svg?style=flat-square)](LICENSE)

# Enterprise Cross-Platform End-to-End Encryption Engine

MegaCrypt is a high-performance cryptographic SDK written in Rust and designed for secure application infrastructure.

It provides a unified encryption layer across:

- Native Rust applications
- Backend services
- Node.js environments
- Browser applications through WebAssembly
- Cross-platform secure communication systems

MegaCrypt focuses on:

- authenticated encryption
- secure key derivation
- encrypted packet transport
- portable cryptographic workflows
- memory-safe implementation

The project is designed for applications requiring strong confidentiality guarantees, including:

- secure messaging platforms
- encrypted APIs
- file protection systems
- WebRTC signaling layers
- confidential application data pipelines

---

# Security Model

MegaCrypt follows a zero-trust encryption architecture.

The library does not implement custom cryptographic algorithms. Instead, it combines established cryptographic primitives through controlled APIs.

## Cryptographic Components

| Component                | Algorithm         | Purpose                                       |
| ------------------------ | ----------------- | --------------------------------------------- |
| Authenticated Encryption | ChaCha20-Poly1305 | Encrypt and authenticate application data     |
| Password Key Derivation  | Argon2id          | Derive encryption keys from user secrets      |
| Hash Derivation          | BLAKE3            | Fast cryptographic hashing and key derivation |
| Random Generation        | OS CSPRNG         | Secure nonce and salt generation              |

---

# Architecture Overview

```

```

                Application Layer

    ┌─────────────────────────────────┐
    │ Chat • API • Storage • Media    │
    └───────────────┬─────────────────┘
                    │

    ┌───────────────┴─────────────────┐
    │          MegaCrypt API           │
    │                                  │
    │  Rust API      WASM API          │
    └───────────────┬─────────────────┘
                    │

    ┌───────────────┴─────────────────┐
    │        Crypto Engine             │
    │                                  │
    │ Key Management                   │
    │ Encryption Contexts              │
    │ Packet Processing                │
    └───────────────┬─────────────────┘
                    │

    ┌───────────────┴─────────────────┐
    │     ChaCha20-Poly1305 AEAD       │
    └─────────────────────────────────┘

```

```

---

# Features

## Core Cryptography

- Authenticated encryption
- Secure key derivation
- Random nonce generation
- Tamper detection
- Portable encrypted packets

## Rust Native Support

- Zero-cost abstractions
- Memory safety guarantees
- Async-compatible integration
- Server-side deployment support

## JavaScript Support

- WebAssembly bindings
- Node.js compatibility
- TypeScript definitions
- Browser-ready encryption APIs

---

# Installation

## Rust

Add MegaCrypt to your `Cargo.toml`:

```toml
[dependencies]
megacrypt = "1.0.0"
```

Then:

```bash
cargo build
```

---

## Node.js / TypeScript

Install using npm:

```bash
npm install megacrypt
```

or:

```bash
pnpm add megacrypt
```

---

# Quick Start

## Rust Example

```rust
use megacrypt::{ CryptoEngine, derive_password_key };
use megacrypt::api::ApiCrypto;
use megacrypt::types::Salt;
use megacrypt::kdf::KdfParams;

fn main() {
    // 1. Create a valid 16-byte salt type
    let salt = Salt::new(*b"megacryptsalt16b");

    // 2. Supply the missing KdfParams argument (using default parameters)
    let key = derive_password_key(b"password", &salt, KdfParams::default()).expect(
        "Failed to derive password key"
    );

    let engine = CryptoEngine::new(key);

    let message = b"confidential message";

    // 3. Encrypt and wrap using the API layer
    let packet = ApiCrypto::encrypt_request(&engine, message);

    // This is what you send to frontend / API
    println!("WEB RESPONSE: {}", packet.data);

    // 4. Decrypt back
    let decrypted = ApiCrypto::decrypt_request(&engine, packet);

    println!("DECRYPTED: {}", String::from_utf8_lossy(&decrypted));
}

```

---

# JavaScript / TypeScript Example

```typescript
import { WasmApiCrypto } from "megacrypt";

const crypto = new WasmApiCrypto("application-secret");

const encoder = new TextEncoder();

const payload = encoder.encode("confidential message");

const encrypted = crypto.encrypt_request(payload);

console.log(encrypted);

const decrypted = crypto.decrypt_request(encrypted);

console.log(new TextDecoder().decode(decrypted));
```
