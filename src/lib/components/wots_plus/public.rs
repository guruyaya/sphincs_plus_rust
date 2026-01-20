use crate::lib::{components::wots_plus::signature::WotsPlusSignature, helpers::{hasher::HashContext, random_generator::{HashData}}};
use sha2::{Digest, Sha256, digest::Update};

#[derive(Debug, Clone)]
pub struct WotsPlusPublic {
    pub context: HashContext,
    pub public_key: HashData
}


impl WotsPlusPublic {
    
    pub fn validate_hash(&self, hash: HashData, sign: &WotsPlusSignature) -> bool {
        sign.clone().get_expected_public_from_hash(&hash) == self.public_key
    }

    pub fn validate_message(&self, _message: &[u8], _sign: &WotsPlusSignature) -> bool {
       let mut message_hash = Sha256::default();
       Update::update(&mut message_hash, _message);
       self.validate_hash(message_hash.finalize().into(), _sign)
    }

    // Size: public_key (32) + public_seed (32) + address (10) = 74
    pub fn to_bytes(&self) -> [u8; 74] {
        todo!()
    }
    
    pub fn from_bytes(_bytes: [u8; 74]) -> Self{
        // Note: This might be tricky due to lifetimes.
        // We need to return an object referencing data that lives long enough.
        todo!()
    }
    
}
