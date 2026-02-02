use crate::lib::{components::{hypertree::public::HyperTreeSignature, merkle_tree::secret::MerkleSigner}, helpers::{hasher::HashContext, random_generator::{Address, HashData}}};

#[derive(Clone, PartialEq)]
pub struct HyperTreeSigner<const LAYERS: usize, const TREE_HEIGHT: usize> {
    seed: HashData,
    pub public_seed: HashData,
}

impl<const LAYERS: usize, const TREE_HEIGHT: usize> HyperTreeSigner<LAYERS, TREE_HEIGHT>{
    pub fn new(seed: HashData, public_seed: HashData) -> Self {
        Self {seed, public_seed}
    }
    
    pub fn generate_master_public_key(&self) -> HashData {
        let context = HashContext{ public_seed: self.public_seed, address: Address {level: (LAYERS - 1) as u16, position: 0} };
        let signer = MerkleSigner::<TREE_HEIGHT>::new(self.seed, context);
        
        let (public_key, _) = signer.get_public_key_and_proof();
        public_key
    }

    pub(super) fn get_tree_pos(self, index: u128, i: usize) -> u128 {
        index >> (i * TREE_HEIGHT)
    }

    pub fn sign(self, fors_public_key: HashData, index: u128) -> HyperTreeSignature<LAYERS, TREE_HEIGHT> {
        let mut current_message = fors_public_key;
        
        let proofs = core::array::from_fn(|i| {
            let pos = self.clone().get_tree_pos(index, i);
            let context = HashContext { 
                public_seed: self.public_seed, 
                address: Address { level: i as u16, position: pos } 
            };
            let signer = MerkleSigner::<TREE_HEIGHT>::new(self.seed, context);
            let proof = signer.sign(&current_message);
            current_message = proof.public_key;
            proof
        });

        HyperTreeSignature { proofs, public_key: self.generate_master_public_key() }
    } 


}
#[cfg(test)]
mod tests {
    use crate::lib::{components::hypertree::secret::HyperTreeSigner, helpers::{hasher::hash_message}};

    #[test]
    fn test_get_public_key() {
        let seed = hash_message("The secret_of_nim".as_bytes());
        let other_seed = hash_message("The secret_of nim".as_bytes());
        let public_seed = hash_message("Never gonna tell you".as_bytes());
        
        let htree = HyperTreeSigner::<2, 3>::new(seed, public_seed);
        let pub_key = htree.generate_master_public_key();
        
        let other_htree = HyperTreeSigner::<2, 3>::new(other_seed, public_seed);
        let other_pub_key = other_htree.generate_master_public_key();
        
        assert_ne!(pub_key, other_pub_key)
    }
    
    #[test]
    fn test_get_pos() {
        let seed = hash_message("The secret_of_nim".as_bytes());
        let public_seed = hash_message("Never gonna tell you".as_bytes());
        
        let htree = HyperTreeSigner::<3, 4>::new(seed, public_seed);
        let pos = htree.clone().get_tree_pos(0b11010010, 0);
        assert_eq!(pos, 0b11010010);

        let pos = htree.clone().get_tree_pos(0b11010010, 1);
        assert_eq!(pos, 0b00001101);

        let pos = htree.clone().get_tree_pos(0b11010010, 2);
        assert_eq!(pos, 0);
    }
    #[test]
    fn test_signtuare() {
        let seed = hash_message("The secret_of_nim".as_bytes());
        let public_seed = hash_message("Never gonna tell you".as_bytes());
        let fors_public_key = hash_message("Drink my juice".as_bytes());
        let other_fors_public_key = hash_message("Drink my Juice".as_bytes());

        let htree = HyperTreeSigner::<2, 3>::new(seed, public_seed);
        let pub_key = htree.generate_master_public_key();

        let signature1 = htree.clone().sign(fors_public_key, 10);
        let signature2 = htree.clone().sign(fors_public_key, 9);
        let signature3 = htree.clone().sign(other_fors_public_key, 10);

        assert_eq!(signature1.proofs.len(), 2);
        assert_eq!(signature1.proofs[0].clone().get_height(), 3);
        assert_ne!(&signature1, &signature2);
        assert_ne!(&signature1, &signature3);
        assert_eq!(pub_key, [221, 80, 43, 100, 45, 35, 
            185, 131, 120, 166, 163, 29, 
            157, 110, 71, 255, 12, 157, 
            212, 185, 29, 220, 144, 0, 
            42, 199, 230, 105, 177, 246, 219, 59])
    }
}