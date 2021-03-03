#![warn(rust_2018_idioms)]

mod matched_data;
#[cfg(feature = "blob_legacy_version")]
mod matched_data_legacy;

use crate::matched_data::generate_key_pair;
use hpke::kex::Serializable;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
struct KeyPair {
    private_key: String,
    public_key: String,
}

#[wasm_bindgen]
pub fn decrypt(private_key: &str, matched_data: &str) -> String {
    let private_key_bytes = radix64::STD
        .decode(&private_key)
        .expect("Cannot decode private key");

    let encrypted_matched_data_bytes = radix64::STD
        .decode(&matched_data)
        .expect("Cannot decode matched data");

    macro_rules! decrypt {
        ($modname:ident) => {{
            use $modname::{decrypt_data, deserialize_encrypted_data, get_private_key_from_bytes};

            let private_key =
                get_private_key_from_bytes(&private_key_bytes).expect("Failed to get private key");

            let encrypted_matched_data_bytes = radix64::STD
                .decode(&matched_data)
                .expect("Cannot decode matched data");

            let encrypted_matched_data = deserialize_encrypted_data(&encrypted_matched_data_bytes)
                .expect("Deserializing encrypted data failed");

            decrypt_data(&encrypted_matched_data, &private_key).expect("Failed to decrypt")
        }};
    }

    // Get encryption version
    let encryption_format_version = encrypted_matched_data_bytes[0];
    let matched_data_for_version = match encryption_format_version {
        #[cfg(feature = "blob_legacy_version")]
        2 => decrypt!(matched_data_legacy),
        3 => decrypt!(matched_data),
        _ => return String::from("Cannot detect version"),
    };

    return String::from_utf8_lossy(&matched_data_for_version).to_string();
}

#[wasm_bindgen]
pub fn keypair() -> JsValue {
    let (private_key, public_key) = generate_key_pair();

    let key_pair = KeyPair {
        private_key: radix64::STD.encode(&private_key.to_bytes()),
        public_key: radix64::STD.encode(&public_key.to_bytes()),
    };

    JsValue::from_serde(&key_pair).unwrap()
}
