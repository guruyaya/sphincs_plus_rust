use crate::lib::{components::merkle_tree::proof::MerkleProof, helpers::random_generator::HashData};

pub enum FailedValidation {
    Proof(usize, HashData, HashData),
    PublicKey(HashData, HashData)
}

#[derive(Clone, PartialEq, Debug)]
pub struct HyperTreeSignature<const LAYERS: usize, const TREE_HEIGHT: usize> {
    pub proofs: [MerkleProof<TREE_HEIGHT>; LAYERS],
    pub public_key: HashData
}

impl<const LAYERS: usize, const TREE_HEIGHT: usize> HyperTreeSignature<LAYERS, TREE_HEIGHT> {
    pub fn get_expected_public_key(self, fors_public_key: HashData) -> Result<HashData, FailedValidation> {
        let mut testing_key = fors_public_key;
        for i in 0..LAYERS {
            if !self.proofs[i].clone().validate_self(&testing_key) {
                return Err(FailedValidation::Proof(i, testing_key, self.proofs[i].clone().public_key));
            }
            testing_key = self.proofs[i].public_key;
        };
        Ok(testing_key)
    }
    pub fn validate(self, fors_public_key: HashData, public_key: HashData) -> Result<HashData, FailedValidation> {
        let testing_key = self.get_expected_public_key(fors_public_key)?;
        match public_key == testing_key {
            true => Ok(public_key),
            false => Err(FailedValidation::PublicKey(public_key, testing_key))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lib::{components::hypertree::secret::HyperTreeSigner, helpers::hasher::hash_message};
    
    #[test]
    fn test_validation_success() {
        let seed = hash_message("The secret_of_nim".as_bytes());
        let public_seed = hash_message("Never gonna tell you".as_bytes());
        let fors_public_key = hash_message("Drink my juice".as_bytes());

        let htree = HyperTreeSigner::<15, 4>::new(seed, public_seed);
        let public_key = htree.generate_master_public_key();

        let signature1 = htree.clone().sign(fors_public_key, 30);
        assert!(signature1.clone().validate(fors_public_key, public_key).is_ok());
    }

    #[test]
    fn test_validation_failures() {
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

        assert!(signature1.clone().validate(fors_public_key, bad_public_key).is_err());
        assert!(signature1.clone().validate(fake_fors_public_key, public_key).is_err());

    }
}