use crate::lib::helpers::{hasher::HashContext, random_generator::{HashData}};

#[derive(Debug)]
pub struct WotsPlusSignature<'a> {
    pub context: &'a HashContext<'a>,
    pub message_hashes: [HashData;32],
    pub checksum_hashes: [HashData;2],
}

impl<'a> WotsPlusSignature<'a> {
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
