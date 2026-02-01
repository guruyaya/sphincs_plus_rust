use crate::lib::{components::merkle_tree::proof::MerkleProof, helpers::random_generator::HashData};

#[derive(Clone, PartialEq, Debug)]
pub struct HyperTreeSignature<const LAYERS: usize, const TREE_HEIGHT: usize> {
    pub proofs: [MerkleProof<TREE_HEIGHT>; LAYERS]
}

impl<const LAYERS: usize, const TREE_HEIGHT: usize> HyperTreeSignature<LAYERS, TREE_HEIGHT> {
    pub fn get_expected_public_key(self, fors_public_key: HashData) -> Option<HashData> {
        let mut testing_key = fors_public_key;
        for i in 0..LAYERS {
            if !self.proofs[i].validate(&testing_key) {
                return None;
            }
            testing_key = self.proofs[i].public_key;
        };
        Some(testing_key)
    }
    pub fn validate(self, fors_public_key: HashData, public_key: HashData) -> bool {
        let result = self.get_expected_public_key(fors_public_key);
        match result {
            None => false,
            Some(testing_key) => public_key == testing_key
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lib::{components::hypertree::secret::HyperTreeSigner, helpers::hasher::hash_message};

    #[test]
    fn test_validation() {
        let seed = hash_message("The secret_of_nim".as_bytes());
        let public_seed = hash_message("Never gonna tell you".as_bytes());
        let fors_public_key = hash_message("Drink my juice".as_bytes());
        let mut fake_fors_public_key = fors_public_key.clone();
        fake_fors_public_key[2] = fake_fors_public_key[2]>>1;

        let htree = HyperTreeSigner::<2, 3>::new(seed, public_seed);
        let public_key = htree.generate_master_public_key();
        let mut bad_public_key = htree.generate_master_public_key();
        bad_public_key[3] = bad_public_key[3] + 1;

        let signature1 = htree.clone().sign(fors_public_key, 10);

        assert!(signature1.clone().validate(fors_public_key, public_key));
        assert!(!signature1.clone().validate(fors_public_key, bad_public_key));
        assert!(!signature1.clone().validate(fake_fors_public_key, public_key));

    }
}