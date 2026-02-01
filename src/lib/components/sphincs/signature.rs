use crate::lib::{components::{fors::{indices::message_to_indices, public::ForsSignature}, hypertree::public::HyperTreeSignature, sphincs::public::SphincsPublic}, helpers::{hasher::hash_message, random_generator::HashData}};

pub struct SignatureValidResult {
    pub data_hash: HashData,
    pub public_key: HashData,
    pub timestamp: u128,
}

#[derive(Debug)]
pub enum SigntureError {
    WrongMessage(HashData),
    ValidationError,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SphincsSignature<const K:usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> {
    pub data_hash: HashData,
    pub fors: ForsSignature<K, A>,
    pub hyper_tree: HyperTreeSignature<LAYERS, TREE_HEIGHT>,
    pub timestamp: u128
}

impl<const K:usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> SphincsSignature<K, A, LAYERS, TREE_HEIGHT> {
    pub fn validate(&self, message: &[u8], public_key: &SphincsPublic<K, A, LAYERS, TREE_HEIGHT>) -> Result<SignatureValidResult, SigntureError> {
        let data_hash = hash_message(message);
        if data_hash != self.data_hash {
            return Err(SigntureError::WrongMessage(self.data_hash));
        }
        let indices = message_to_indices::<K, A>(message);

        let fors_key = self.fors.clone().get_expected_public_from_hash(indices);
        let result = self.hyper_tree.clone().validate(fors_key, public_key.key);
        
        match result {
            false => Err(SigntureError::ValidationError),
            true => Ok(SignatureValidResult{data_hash, public_key: public_key.key, timestamp: self.timestamp})
        }
        
    }
}
