use crate::lib::{components::{fors::public, wots_plus::signature::WotsPlusSignature}, helpers::{hasher::hash_array, random_generator::HashData}};

#[derive(Clone, Debug, PartialEq)]
pub struct MerkleProof<const HEIGHT:usize> { // STEM_HEIGHT does not include the root level
    pub public_key: HashData,
    pub signature: WotsPlusSignature,
    pub merkle_leaves: [HashData;HEIGHT]
}

impl<const HEIGHT:usize> MerkleProof<HEIGHT> {
    pub fn get_height(self) -> usize {
        HEIGHT
    }
    pub fn get_expected_public_key(self, message: &[u8]) -> HashData{
        let this_signature = self.signature.clone();
        let num_keys = (2 as usize).pow(HEIGHT as u32);
        
        let mut key = this_signature.get_expected_public_from_message(message);
        let mut key_idx = this_signature.context.address.position as usize % num_keys;
        
        for other_key in self.merkle_leaves {
            if key_idx % 2 == 1{
                key = hash_array(&[other_key, key, self.signature.context.public_seed])
            }else{
                key = hash_array(&[key, other_key, self.signature.context.public_seed])
            }
            key_idx = key_idx / 2
        };
        key
    }
    pub fn validate(self, message: &[u8], public_key: HashData)-> bool {
        let key = self.get_expected_public_key(message);
        public_key == key
    }
    pub fn validate_self(self, message: &[u8])-> bool {
        let pkey = &self.public_key.clone();
        self.validate(&message, *pkey)
    }
}
