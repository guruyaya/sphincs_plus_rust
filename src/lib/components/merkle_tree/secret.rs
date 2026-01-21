use std::hash::Hash;

use crate::lib::{
    components::wots_plus::{public::WotsPlusPublic, secret::WotsPlus, signature::WotsPlusSignature}, helpers::{hasher::HashContext, random_generator::HashData}
};

pub enum MerkleProofError {
    GeneralError
}
pub struct MerkleProof<const TREE_HEIGHT:usize> { // TREE_HEIGHT is Signer.height-1
    pub public_key: HashData,
    pub message_hash: HashData,
    pub signature: WotsPlusSignature,
    pub merkle_leaves: [HashData;TREE_HEIGHT]
}

pub struct MerkleSigner<const TREE_HEIGHT:usize> {
    seed: HashData,
    pub context: HashContext,
    pub height: usize,

}

impl<const TREE_HEIGHT:usize> MerkleSigner<TREE_HEIGHT> {
    pub fn new(seed: HashData, context:HashContext) -> Self {
        // valiadte the context address
        // return self
        todo!();
    }

    pub fn sign(&self, message: &[u8]) -> Result<MerkleProof<TREE_HEIGHT>, MerkleProofError>{
        todo!()
    }
}

#[macro_export]
macro_rules! merkle_signer {
    ($height:expr, $seed: expr, $context: expr) => {
        // taking one down to repesent the real height
        $crate::lib::components::merkle_tree::secret::MerkleSigner::<{ $height - 1 }>::new($seed, $context)
    };
}

#[cfg(test)]
mod tests {
    use crate::lib::helpers::hasher::HashContext;

    #[test]
    fn test_create_merkle_signer() {
        let context = HashContext::default();
        merkle_signer!(4, [0u8;32], context);
    }
}