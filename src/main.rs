#![no_std]
#![cfg_attr(not(feature = "export-abi"), no_main)]
extern crate alloc;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

use alloc::{format, vec, vec::Vec};
use stylus_sdk::{abi::Bytes, prelude::*};

mod bls;

const SIG_LEN: usize = 96;
const PUBKEY_LEN: usize = 48;

#[solidity_storage]
#[entrypoint]
pub struct BLSVerifier;

#[external]
impl BLSVerifier {
    pub fn verify_bls_signature(&self, data: Bytes) -> Result<(), Vec<u8>> {
        if data.len() <= PUBKEY_LEN + SIG_LEN {
            return Err("data does not include signed message".as_bytes().to_vec());
        }
        let mut data = data.as_slice();
        let sig = &data[..SIG_LEN];
        data = &data[SIG_LEN..];
        let pubkey = &data[..PUBKEY_LEN];
        data = &data[PUBKEY_LEN..];
        let msg = &data;
        match bls::verify_bls_signature(sig, msg, pubkey) {
            Ok(()) => Ok(()),
            Err(()) => Err("sig failed to verify".as_bytes().to_vec()),
        }
    }
}
