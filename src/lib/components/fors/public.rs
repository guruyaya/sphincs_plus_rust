use crate::lib::helpers::{hasher::HashContext, random_generator::HashData};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForsSignatureElement<const A: usize> {
    pub secret_key: HashData,
    pub auth_path: [HashData; A],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForsSignature<const K: usize, const A: usize> {
    pub signatures: [ForsSignatureElement<A>; K],
}
impl<const K: usize, const A: usize> ForsSignature<K, A> { 
    fn validate(self, message: &[u8], context: HashContext, public_key: HashData) -> bool {
        todo!()
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
        let context = HashContext::default();
        let fors: Fors<14, 10> = Fors::new(HASH_DATA_0, HashContext { public_seed: HASH_DATA_0, address: Address::default() });
        let public_key = fors.generate_public_key();
        let signature = fors.sign(MESSAGE);
        // Validate the signatue for the right message using ForsSignature.validate()
        assert!(signature.clone().validate(MESSAGE, context.clone(), public_key));
        
        // Validate the signatue fails for the wrong message using ForsSignature.validate()
        assert!(!signature.clone().validate(OTHER_MESSAGE, context.clone(), public_key));

        // Validate the signatue fails for the right message using ForsSignature.validate() with garbeled key 
        let mut garbeled_key = public_key.clone();
        garbeled_key[2] += 1;
        assert!(!signature.clone().validate(MESSAGE, context.clone(), garbeled_key));
        
        // Validate the signatue fails for the right message using ForsSignature.validate() with garbeled public_seed
        let mut other_context = context.clone();
        other_context.public_seed[2] += 1;
        assert!(!signature.clone().validate(MESSAGE, other_context, public_key));
    }
}