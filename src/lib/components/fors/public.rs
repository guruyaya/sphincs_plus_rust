use crate::lib::{components::{fors::indices::message_to_indices}, helpers::{hasher::{HashContext, hash_array, hash_message}, random_generator::HashData}};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForsSignatureElement<const A: usize> {
    pub secret_key: HashData,
    pub auth_path: [HashData; A],
}

#[derive(Debug, Clone, PartialEq)]
pub struct ForsSignature<const K: usize, const A: usize> {
    pub signatures: [ForsSignatureElement<A>; K],
    pub context: HashContext,
    pub public_key: HashData
}
impl<const K: usize, const A: usize> ForsSignature<K, A> {
    pub fn get_expected_public_from_hash(self, indices: [u32; K]) -> HashData {
        let hashed_collection:[HashData; K] = std::array::from_fn(|i|{
            let signature = &self.signatures[i];
            let mut idx = indices[i];
            let mut hashed_level = hash_message(&signature.secret_key);
            for j in 0..A {
                let pair = if idx % 2 == 1{
                    [signature.auth_path[j], hashed_level, self.context.public_seed]
                } else{
                    [hashed_level, signature.auth_path[j], self.context.public_seed]
                };
                hashed_level = hash_array(&pair);
                idx /= 2;
            };
            hashed_level
        });
        hash_array(&hashed_collection)
    } 

    pub fn validate(self, message: &[u8], public_key: HashData) -> bool {
        let indices = message_to_indices::<K, A>(message);

        self.get_expected_public_from_hash(indices) == public_key
    }

    
    pub fn validate_self(self, message: &[u8]) -> bool {
        let public_key = self.public_key.clone();
        self.validate(message, public_key)
    }


}

#[cfg(test)]
mod tests {
    use crate::lib::{components::fors::secret::Fors, helpers::{hasher::{HashContext, hash_message}, random_generator::{Address, HASH_DATA_0, HashData}}};

    #[test]
    fn test_signature_validation() {
        // Set 2 messages, one will be signed, and one will be checked against the signature, and fail
        const MESSAGE:&[u8] = "Hello from rust".as_bytes();
        const OTHER_MESSAGE:&[u8] = "HEllo from rust".as_bytes();
        let seed:HashData = hash_message("Secret rust stuff".as_bytes());

        // Sign the message using Fors.sign()
        let fors: Fors<14, 10> = Fors::new(seed, HashContext { public_seed: HASH_DATA_0, address: Address::default() });
        let public_key = fors.generate_public_key();
        let signature = fors.sign(MESSAGE);
        // Validate the signatue for the right message using ForsSignature.validate()
        assert!(signature.clone().validate(MESSAGE, public_key));
        
        // Validate the signatue fails for the wrong message using ForsSignature.validate()
        assert!(!signature.clone().validate(OTHER_MESSAGE, public_key));

        // Validate the signatue fails for the right message using ForsSignature.validate() with garbeled key 
        let mut garbeled_key = public_key.clone();
        garbeled_key[2] += 1;
        assert!(!signature.clone().validate(MESSAGE, garbeled_key));
    }
}