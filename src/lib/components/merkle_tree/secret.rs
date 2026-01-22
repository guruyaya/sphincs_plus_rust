use std::hash::Hash;

use crate::lib::{
    components::wots_plus::{public::WotsPlusPublic, secret::WotsPlus, signature::WotsPlusSignature}, helpers::{hasher::HashContext, random_generator::HashData}
};

pub struct MerkleProof<const TREE_HEIGHT:usize> { // TREE_HEIGHT is Signer.height-1
    pub public_key: HashData,
    pub message_hash: HashData,
    pub signature: WotsPlusSignature,
    pub merkle_leaves: [HashData;TREE_HEIGHT]
}


#[derive(Debug)]
pub struct MerkleSigner<const TREE_HEIGHT:usize> {
    seed: HashData,
    pub context: HashContext,
}

impl<const STEM_HEIGHT:usize> MerkleSigner<STEM_HEIGHT> {
    pub fn new(seed: HashData, context:HashContext) -> Self {
        Self{seed, context}
    }
    pub fn get_height(&self) -> usize{
        // returns the full size of the tree
        STEM_HEIGHT + 1
    }
    pub fn sign(&self, message: &[u8]) -> MerkleProof<STEM_HEIGHT> {
        todo!()
    }
}

#[macro_export]
macro_rules! merkle_signer {
    ($tree_height:expr, $seed: expr, $context: expr) => {
        // taking one down to repesent the full tree height, including the root
        $crate::lib::components::merkle_tree::secret::MerkleSigner::<{ $tree_height - 1 }>::new($seed, $context)
    };
}

#[cfg(test)]
mod tests {
    use crate::lib::{helpers::{hasher::HashContext}};

    #[test]
    fn test_create_merkle_signer() {
        let context = HashContext::default();
        let signer = merkle_signer!(4, [0u8;32], context);

        assert_eq!(signer.get_height(), 4);
    }
}