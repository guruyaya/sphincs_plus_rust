use crate::lib::{components::wots_plus::signature::WotsPlusSignature, helpers::{hasher::{HashContext, hash_message}, random_generator::HashData}};

#[derive(Debug, Clone, PartialEq)]
pub struct WotsPlusPublic {
    pub public_key: HashData,
    pub context: HashContext,
}


impl WotsPlusPublic {
    
    pub fn validate_hash(&self, hash: HashData, sign: &WotsPlusSignature) -> bool {
        sign.clone().get_expected_public_from_hash(hash) == self.public_key
    }

    pub fn validate_message(&self, message: &[u8], _sign: &WotsPlusSignature) -> bool {
        let message_hash = hash_message(message);
        self.validate_hash(message_hash, _sign)
    }
    
}
