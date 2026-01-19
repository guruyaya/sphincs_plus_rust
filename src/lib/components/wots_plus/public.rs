use crate::lib::{components::wots_plus::signature::WotsPlusSignature, helpers::random_generator::{Address, HashData}};


#[derive(Debug)]
pub struct WotsPlusPublic<'a> {
    pub start_address: &'a Address,
    pub public_seed: HashData,
    pub public_key: HashData
}


impl<'a> WotsPlusPublic<'a> {
    
    pub fn validate_hash(&self, _hash: HashData, _sign: &WotsPlusSignature) -> bool {
        todo!()
    }

    pub fn validate_message(&self, _message: &[u8], _sign: &WotsPlusSignature) -> bool {
        todo!()
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        todo!()
    }
    
    pub fn from_bytes(_bytes: [u8; 42]) -> Self{
        todo!()
    }
    
}
