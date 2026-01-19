use crate::lib::helpers::random_generator::{Address, HashData};

#[derive(Debug)]
pub struct WotsPlusSignature {
    start_address: Address,
    public_seed: HashData,

    message_hashes: [HashData;32],
    checksum_hashes: [HashData;2],
}

impl WotsPlusSignature {
    pub fn new(start_address: Address, public_seed: HashData, message_hashes: [HashData;32], checksum_hashes: [HashData; 2]) {
        todo!();
    }
    pub fn calculate_target_key(&self) -> HashData {
        todo!()
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        todo!()
    }
    
    pub fn from_bytes(_bytes: [u8; 42]) -> Self{
        todo!()
    }
}
