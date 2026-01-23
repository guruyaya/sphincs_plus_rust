use crate::lib::{
    components::wots_plus::{secret::WotsPlus, signature::WotsPlusSignature}, helpers::{hasher::{HashContext}, random_generator::{Address, HashData}}
};

pub struct MerkleProof<const STEM_HEIGHT:usize> { // STEM_HEIGHT does not include the root level
    pub public_key: HashData,
    pub signature: WotsPlusSignature,
    pub merkle_leaves: [HashData;STEM_HEIGHT]
}

impl<const STEM_HEIGHT:usize> MerkleProof<STEM_HEIGHT> {
    fn validate(&self, message: &[u8])-> bool {
        self.signature.clone().get_expected_public_from_message(message);
        todo!()
    }
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
        // returns the full size of the tree, not the stem
        STEM_HEIGHT + 1
    }
    pub(super) fn generate_lowest_layer(&self) -> Vec<WotsPlus> {
        let num_trees: u64 = (2 as u64).pow((STEM_HEIGHT + 1) as u32);
        let position = self.context.address.position;
        let level = self.context.address.level;
        let public_seed = self.context.public_seed;
        let first_postion = (position / &num_trees) * &num_trees;
        let next_tree_position = first_postion + num_trees;
        (first_postion..next_tree_position).map(|pos| {
            WotsPlus::new(self.seed.clone(), HashContext { public_seed, address: Address{level, position: pos} })
        }).collect()
    }
    pub(super) fn get_signer_proof_and_public_key(&self, lowest_layer: Vec<WotsPlus>) -> (HashData, [HashData;STEM_HEIGHT], WotsPlus){
        todo!()
    }
    pub(super) fn sign(&self, message: &[u8]) -> MerkleProof<STEM_HEIGHT> {
        let lowest_layer = self.generate_lowest_layer();
        let (public_key, merkle_leaves, signer_wots) = self.get_signer_proof_and_public_key(lowest_layer);
        let signature = signer_wots.sign_message(message);

        MerkleProof { public_key, signature, merkle_leaves }
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

    #[test]
    fn test_generate_lowest_layer() {
        let context = HashContext::default();
        
        let signer = merkle_signer!(4, [0u8;32], context.clone());
        let lowest_layer = signer.generate_lowest_layer();
        assert_eq!(lowest_layer[0].context, context);
        assert_eq!(lowest_layer.len(), 16);
        
        let mut other_context = context.clone();
        other_context.address.position = 123;
        let signer = merkle_signer!(4, [0u8;32], other_context.clone());
        let lowest_layer = signer.generate_lowest_layer();
        assert_eq!(lowest_layer[11].context, other_context);
        assert_eq!(lowest_layer.len(), 16);
        
        let mut another_context = context.clone();
        another_context.address.position = 1074;
        let signer = merkle_signer!(8, [0u8;32], another_context.clone());
        let lowest_layer = signer.generate_lowest_layer();
        assert_eq!(lowest_layer[50].context, another_context);
        assert_eq!(lowest_layer.len(), 256);
        for i in 1..256 {
            assert_eq!(lowest_layer[i].context.address.position - 1, lowest_layer[i-1].context.address.position)
        }
    }
    
    #[test]
    fn test_get_signer_proof_and_public_key() {
        let context = HashContext::default();
        
        let signer = merkle_signer!(4, [0u8;32], context.clone());
        let lowest_layer = signer.generate_lowest_layer();
        let (public_key, merkle_leaves, signer_wots) = signer.get_signer_proof_and_public_key(lowest_layer);
        assert_eq!(merkle_leaves.len(), 3);
        assert_eq!(public_key, [0u8;32]);
        assert_ne!(signer_wots.generate_public_key().public_key, public_key);
        

    }
    #[test]
    fn test_signature_on_message() {
        const MESSAGE:&[u8] = "Hello from Rust".as_bytes();
        const OTHER_MESSAGE:&[u8] = "Hello from Rusty".as_bytes();
        let context = HashContext::default();
        let signer = merkle_signer!(4, [0u8;32], context);

        let signature = signer.sign(MESSAGE);
        assert!(signature.validate(MESSAGE));   
        assert!(!signature.validate(OTHER_MESSAGE));       
    }
}