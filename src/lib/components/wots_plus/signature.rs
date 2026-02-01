use sha2::{Digest, Sha256, digest::Update};
use crate::lib::helpers::{hasher::{HashContext, complement_hash, hash_array}, random_generator::{HASH_DATA_0, HashData}};

pub const MAX_HASHES_NEEDED:u16 = 255 * 32;

pub struct ValidWotsPSignature (HashData, HashContext); // public key, context
pub struct InvalidWotsPSignature (HashData, HashData, HashContext); // calculated public key, public key, context

#[derive(Debug,Clone, PartialEq)]
pub struct WotsPlusSignature {
    pub context: HashContext,
    pub message_hashes: [HashData;32],
    pub checksum_hashes: [HashData;2],
    pub public_key: HashData
}

impl<'a> WotsPlusSignature {
    pub fn get_expected_public_from_hash(self, message_hash: HashData) -> HashData {
        let mut count_hashes_left: u16 = MAX_HASHES_NEEDED;
        let mut out = [HASH_DATA_0;34];

        for (index, times_repeated) in message_hash.into_iter().enumerate() {
            let key = self.message_hashes[index];
            out[index] = complement_hash(key, times_repeated.clone(), &self.context);
            count_hashes_left -= times_repeated.clone() as u16; 
        };
        
        let two_bytes = count_hashes_left.to_le_bytes();

        for (index, times_to_repeat) in two_bytes.into_iter().enumerate() {
            let key = self.checksum_hashes[index];
            out[32 + index] = complement_hash(key, times_to_repeat.clone(), &self.context);
        };

        hash_array(&out)
    }

    pub fn get_expected_public_from_message(&self, message:&[u8]) -> HashData {
        let mut message_hash = Sha256::default();
        Update::update(&mut message_hash, message);
        self.clone().get_expected_public_from_hash(message_hash.finalize().into())
    }

    pub fn validate_self(self, message_hash: HashData) -> Result<ValidWotsPSignature, InvalidWotsPSignature> {
        let calculated_key = self.clone().get_expected_public_from_hash(message_hash);
        match self.public_key == calculated_key {
            true => Ok(ValidWotsPSignature(self.public_key, self.context.clone())),
            false => Err(InvalidWotsPSignature(calculated_key, self.public_key, self.context.clone()))
        }
    }
    
}