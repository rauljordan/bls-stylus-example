// Most code from https://github.com/dfinity/verify-bls-signatures/blob/master/src/lib.rs
// modified quite a bit to allow public keys in G1 and signatures in G2.
#![allow(clippy::result_unit_err)]
#![allow(dead_code)]

use core::ops::Neg;

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G2Affine, G2Prepared, G2Projective};
use pairing::group::{Curve, Group};

// This domain separation for BLS signatures is the same one that Ethereum mainnet uses.
const BLS_SIGNATURE_DOMAIN_SEP: [u8; 43] = *b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn hash_to_g2(msg: &[u8]) -> G2Affine {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(
        msg,
        &BLS_SIGNATURE_DOMAIN_SEP,
    )
    .to_affine()
}

/// A BLS12-381 public key usable for signature verification
#[derive(Clone, Eq, PartialEq)]
pub struct PublicKey {
    pk: G1Affine,
}
/// An error indicating an encoded public key was not valid
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum InvalidPublicKey {
    /// The public key encoding was not the correct length
    WrongLength,
    /// The public key was not a valid BLS12-381 G2 point
    InvalidPoint,
}

impl PublicKey {
    /// The length of the binary encoding of this type
    pub const BYTES: usize = 48;

    fn new(pk: G1Affine) -> Self {
        Self { pk }
    }

    /// Deserialize a BLS12-381 public key
    pub fn deserialize(bytes: &[u8]) -> Result<Self, InvalidPublicKey> {
        let bytes: Result<[u8; Self::BYTES], _> = bytes.try_into();

        match bytes {
            Err(_) => Err(InvalidPublicKey::WrongLength),
            Ok(b) => {
                let pk = G1Affine::from_compressed(&b);
                if bool::from(pk.is_some()) {
                    Ok(Self::new(pk.unwrap()))
                } else {
                    Err(InvalidPublicKey::InvalidPoint)
                }
            }
        }
    }

    /// Verify a BLS signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), ()> {
        let msg = hash_to_g2(message);
        let g1_gen: G1Affine = G1Affine::generator().neg();
        let pk = G1Affine::from(self.pk);
        let prepared_sig = G2Prepared::from(signature.sig);

        let sig_g2 = (&g1_gen, &prepared_sig);
        let msg_pk = (&pk, &msg.into());

        let x = multi_miller_loop(&[sig_g2, msg_pk]).final_exponentiation();

        if bool::from(x.is_identity()) {
            Ok(())
        } else {
            Err(())
        }
    }
}

/// An error indicating a signature could not be deserialized
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum InvalidSignature {
    /// The signature encoding is the wrong length
    WrongLength,
    /// The signature encoding is not a valid BLS12-381 G1 point
    InvalidPoint,
}

/// A type expressing a BLS12-381 signature
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Signature {
    sig: G2Affine,
}

impl Signature {
    /// The length of the binary encoding of this type
    pub const BYTES: usize = 96;

    fn new(sig: G2Affine) -> Self {
        Self { sig }
    }

    /// Deserialize a BLS signature
    pub fn deserialize(bytes: &[u8]) -> Result<Self, InvalidSignature> {
        let bytes: Result<[u8; Self::BYTES], _> = bytes.try_into();

        match bytes {
            Err(_) => Err(InvalidSignature::WrongLength),
            Ok(b) => {
                let sig = G2Affine::from_compressed(&b);
                if bool::from(sig.is_some()) {
                    Ok(Self::new(sig.unwrap()))
                } else {
                    Err(InvalidSignature::InvalidPoint)
                }
            }
        }
    }
}

/// Verify a BLS signature
///
/// The signature must be exactly 48 bytes (compressed G1 element)
/// The key must be exactly 96 bytes (compressed G2 element)
pub fn verify_bls_signature(sig: &[u8], msg: &[u8], key: &[u8]) -> Result<(), ()> {
    let sig = Signature::deserialize(sig).map_err(|_| ())?;
    let pk = PublicKey::deserialize(key).map_err(|_| ())?;
    pk.verify(msg, &sig)
}
