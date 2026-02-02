use crate::lib::{
    components::wots_plus::{secret::WotsPlus}, helpers::{hasher::{HashContext, hash_array}, random_generator::{Address, HashData}}
};
use super::proof::MerkleProof;

pub(crate) fn pair_keys(keys: &[HashData], public_seed: HashData) -> Vec<HashData> {
    assert!(keys.len().is_multiple_of(2), "Number of keys provided to pair_keys must be devisible by 2");
    (0..keys.len()).step_by(2).map(|idx| {
        hash_array(&[keys[idx], keys[idx+1], public_seed])
    }).collect()
}

#[derive(Debug)]
pub struct MerkleSigner<const HEIGHT:usize> {
    seed: HashData,
    num_trees: u64,
    pub context: HashContext,
    
}

impl<const HEIGHT:usize> MerkleSigner<HEIGHT> {
    pub fn new(seed: HashData, context:HashContext) -> Self {
        let num_trees: u64 = (2_u64).pow((HEIGHT) as u32);
        Self{seed, context, num_trees}
    }
    pub fn get_height(&self) -> usize{
        // returns the full size of the tree, not the stem
        HEIGHT
    }
    pub(super) fn generate_lowest_layer(&self) -> Vec<WotsPlus> {
        
        let position = self.context.address.position;
        let level = self.context.address.level;
        let public_seed = self.context.public_seed;
        let first_postion = (position / (self.num_trees as u128)) * (self.num_trees as u128);
        let next_tree_position = first_postion + self.num_trees as u128;
        (first_postion..next_tree_position).map(|pos| {
            WotsPlus::new(self.seed, HashContext { public_seed, address: Address{level, position: pos} })
        }).collect()
    }

    pub fn get_signing_wots(&self, lowest_layer: &[WotsPlus]) -> WotsPlus {
        let wots_idx:usize = self.context.address.position as usize % self.num_trees as usize;
        lowest_layer[wots_idx].clone()
    }

    pub fn get_public_key_and_proof(self)  -> (HashData, [HashData;HEIGHT]){
        let lowest_layer = self.generate_lowest_layer();
        self._get_public_key_and_proof(lowest_layer)
    }
    fn _get_public_key_and_proof(&self, lowest_layer: Vec<WotsPlus>) -> (HashData, [HashData;HEIGHT]){
        let mut public_keys: Vec<HashData> = lowest_layer.iter().map(|wots| wots.generate_public_key().public_key).collect();
        let mut hashed_idx = self.context.address.position as usize % self.num_trees as usize;
        let merkle_proof  = core::array::from_fn(|_| {
            let other_key = if hashed_idx % 2 == 1 {
                public_keys[hashed_idx - 1]
            } else {
                public_keys[hashed_idx + 1]
            };
            hashed_idx /= 2;
            public_keys = pair_keys(&public_keys, self.context.public_seed);
            other_key
        });
        (public_keys[0], merkle_proof)
    }

    pub fn sign(&self, message: &[u8]) -> MerkleProof<HEIGHT> {
        let lowest_layer = self.generate_lowest_layer();
        let signing_wots = self.get_signing_wots(&lowest_layer);
        let (public_key, merkle_leaves) = self._get_public_key_and_proof(lowest_layer);
        let signature = signing_wots.sign_message(message);

        MerkleProof { public_key, signature, merkle_leaves }
    }
}

#[macro_export]
macro_rules! merkle_signer {
    ($tree_height:expr, $seed: expr, $context: expr) => {
        // taking one down to repesent the full tree height, including the root
        $crate::lib::components::merkle_tree::secret::MerkleSigner::<{ $tree_height }>::new($seed, $context)
    };
}

#[cfg(test)]
mod tests {
    use crate::lib::components::merkle_tree::secret::pair_keys;
    use crate::lib::helpers::hasher::hash_message;
    use crate::lib::helpers::random_generator::Address;
    use crate::lib::helpers::{hasher::HashContext, random_generator::HASH_DATA_0};

    #[test]
    fn test_create_merkle_signer() {
        let context = HashContext::default();
        let signer = merkle_signer!(4, HASH_DATA_0, context);

        assert_eq!(signer.get_height(), 4);
    }

    #[test]
    fn test_generate_lowest_layer() {
        let context = HashContext::default();
        
        let signer = merkle_signer!(4, HASH_DATA_0, context.clone());
        let lowest_layer = signer.generate_lowest_layer();
        assert_eq!(lowest_layer[0].context, context);
        assert_eq!(lowest_layer.len(), 16);
        
        let mut other_context = context.clone();
        other_context.address.position = 123;
        let signer = merkle_signer!(4, HASH_DATA_0, other_context.clone());
        let lowest_layer = signer.generate_lowest_layer();
        assert_eq!(lowest_layer[11].context, other_context);
        assert_eq!(lowest_layer.len(), 16);
        
        let mut another_context = context.clone();
        another_context.address.position = 1074;
        let signer = merkle_signer!(8, HASH_DATA_0, another_context.clone());
        let lowest_layer = signer.generate_lowest_layer();
        assert_eq!(lowest_layer[50].context, another_context);
        assert_eq!(lowest_layer.len(), 256);
        for i in 1..256 {
            assert_eq!(lowest_layer[i].context.address.position - 1, lowest_layer[i-1].context.address.position)
        }
    }

    #[test]
    fn test_pair_keys (){
        let public_seed = HASH_DATA_0;
        let to_join = vec!(
            hash_message("a".as_bytes()), hash_message("b".as_bytes()), 
            hash_message("a".as_bytes()), hash_message("b".as_bytes()), // Note: the first 2 are the same
            hash_message("a".as_bytes()), hash_message("c".as_bytes()),
            hash_message("a".as_bytes()), hash_message("d".as_bytes()));
        let keys = pair_keys(&to_join, public_seed);
        assert_eq!(keys.len(), 4);
        assert_eq!(keys[0], keys[1]);
        assert_ne!(keys[0], keys[2]);
        assert_ne!(keys[0], keys[3]);
        assert_ne!(keys[2], keys[3]);
        
        let more_keys = pair_keys(&keys, public_seed);
        
        assert_eq!(more_keys.len(), 2);
        assert_ne!(more_keys[0], more_keys[1]);
        
        let one_key = pair_keys(&more_keys, public_seed);
        
        assert_eq!(one_key.len(), 1);
    }
    #[test]
    fn test_paring_seed_effect() {
        let public_seed1 = HASH_DATA_0;
        let public_seed2 = HASH_DATA_0;
        let mut public_seed3 = HASH_DATA_0;
        public_seed3[0] = 1;

        let to_join = vec!(
            hash_message("a".as_bytes()), hash_message("b".as_bytes()), 
        );
        let result1 = pair_keys(&to_join.clone(), public_seed1);
        let result2 = pair_keys(&to_join.clone(), public_seed2);
        let result3 = pair_keys(&to_join.clone(), public_seed3);

        assert_eq!(result1, result2);
        assert_ne!(result1, result3);

    }
    #[test]
    #[should_panic(expected = "Number of keys provided to pair_keys must be devisible by 2")]
    fn test_pair_keys_panics() {
        let public_seed = HASH_DATA_0;
        let to_join = vec!(
            hash_message("a".as_bytes()), hash_message("b".as_bytes()), 
            hash_message("a".as_bytes()), hash_message("b".as_bytes()), // Note: the first 2 are the same
            hash_message("a".as_bytes()), hash_message("c".as_bytes()),
            hash_message("a".as_bytes()) );
        let _ = pair_keys(&to_join, public_seed);
    }
    #[test]
    fn test_get_signing_wots() {
        let mut context = HashContext::default();
        context.address.position = 19;

        let signer = merkle_signer!(4, HASH_DATA_0, context.clone());
        let lowest_layer = signer.generate_lowest_layer();
        let signer_wots = signer.get_signing_wots(&lowest_layer);
        assert_eq!(signer_wots.context, signer.context);
        assert_eq!(signer_wots, lowest_layer[3]); // 3 = context.address.position % 16
    }
    
    #[test]
    fn test_get_proof_and_public_key() {
        let context = HashContext::default();
        
        let signer = merkle_signer!(4, HASH_DATA_0, context);
        let (public_key, merkle_leaves) = signer.get_public_key_and_proof();
        assert_eq!(merkle_leaves.len(), 4);
        // This checks if the key is stable over tests
        assert_eq!( public_key, [204, 69, 137, 115, 70, 125, 219, 78, 237, 
            239, 133, 114, 169, 95, 104, 171, 2, 29, 144, 58, 193, 173, 140, 
            205, 252, 155, 196, 182, 175, 190, 159, 181] );
        
        let mut other_context = HashContext::default();
        other_context.address.position = 11;
        
        let signer = merkle_signer!(4, HASH_DATA_0, other_context);
        let lowest_layer = signer.generate_lowest_layer();
        let (other_public_key, merkle_leaves) = signer._get_public_key_and_proof(lowest_layer);
        assert_eq!(merkle_leaves.len(), 4);
        assert_eq!(other_public_key, public_key)
    }
    #[test]
    fn test_signature_on_message() {
        const SEED_CREATOR:&[u8] = "Seed of evil".as_bytes();
        const MESSAGE:&[u8] = "Hello from Rust".as_bytes();
        const OTHER_MESSAGE:&[u8] = "Hello from Rusty".as_bytes();

        let context = HashContext{ public_seed: hash_message(SEED_CREATOR), address: Address{level: 12, position:123} };
        
        let signer = merkle_signer!(4, HASH_DATA_0, context);

        let signature = signer.sign(MESSAGE);
        assert!(signature.clone().validate_self(MESSAGE));   
        assert!(!signature.validate_self(OTHER_MESSAGE));       
    }
}
