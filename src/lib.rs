use bincode::ErrorKind;
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    kex::{Deserializable, KeyExchange, Serializable},
    EncappedKey, HpkeError, Kem as KemTrait, OpModeR,
};
use rand::{rngs::StdRng, rngs::OsRng, SeedableRng};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type Kex = <Kem as KemTrait>::Kex;

const ENCRYPTION_FORMAT_VERSION: u8 = 1;

#[wasm_bindgen]
pub fn decrypt(private_key: &str, matched_data: &str) -> String {
    let private_key_bytes = radix64::STD
        .decode(&private_key)
        .expect("Cannot decode private key");
    let private_key =
        get_private_key_from_bytes(&private_key_bytes).expect("Failed to get private key");

    let encrypted_matched_data_bytes = radix64::STD
        .decode(&matched_data)
        .expect("Cannot decode matched data");
    let encrypted_matched_data = deserialize_encrypted_data(&encrypted_matched_data_bytes)
        .expect("Deserializing encrypted data failed");

    let matched_data =
        decrypt_data(&encrypted_matched_data, &private_key).expect("Failed to decrypt");

    return String::from_utf8_lossy(&matched_data).to_string();
}

#[derive(Serialize, Deserialize)]
struct KeyPair {
    private_key: String,
    public_key: String,
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

#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    encapped_key: EncappedKey<Kex>,
    ciphertext: Vec<u8>,
    tag: AeadTag<Aead>,
}

// Generates a public-private key pair
pub fn generate_key_pair() -> (
    <Kex as KeyExchange>::PrivateKey,
    <Kex as KeyExchange>::PublicKey,
) {
    let mut csprng = StdRng::from_entropy();
    Kem::gen_keypair(&mut csprng)
}

// Constructs a PrivateKey from an array of bytes
pub fn get_private_key_from_bytes(
    private_key_bytes: &[u8],
) -> Result<<Kex as KeyExchange>::PrivateKey, HpkeError> {
    <Kex as KeyExchange>::PrivateKey::from_bytes(private_key_bytes)
}

// Decrypts data with provided private key
pub fn decrypt_data(
    encrypted_data: &EncryptedData,
    private_key: &<Kex as KeyExchange>::PrivateKey,
) -> Result<Vec<u8>, HpkeError> {
    // Decapsulate and derive the shared secret. Create a shared AEAD context.
    let mut aead_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private_key,
        &encrypted_data.encapped_key,
        &[],
    )?;

    // Decrypt ciphertext in place
    let mut ciphertext_copy = encrypted_data.ciphertext.to_vec();
    aead_ctx.open(&mut ciphertext_copy, &[], &&encrypted_data.tag)?;

    // Rename for clarity
    let plaintext = ciphertext_copy;

    Ok(plaintext)
}

// Deserializes an array of bytes using bincode into encrypted data
pub fn deserialize_encrypted_data(
    serialized_encrypted_data: &[u8],
) -> Result<EncryptedData, Box<ErrorKind>> {
    // Ensure the serialized data used the same format version
    let encryption_format_version = serialized_encrypted_data[0];
    if encryption_format_version != ENCRYPTION_FORMAT_VERSION {
        return Err(ErrorKind::Custom(format!(
            "Encryption format mismatch, expected '{}', got '{}'",
            ENCRYPTION_FORMAT_VERSION, encryption_format_version,
        ))
        .into());
    }

    bincode::deserialize(&serialized_encrypted_data[1..])
}
