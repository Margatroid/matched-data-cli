use crate::matched_data_cli;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn decrypt(private_key: &str, matched_data: &str) -> bool {
    let private_key_bytes = radix64::STD.decode(&private_key);
    false
}
