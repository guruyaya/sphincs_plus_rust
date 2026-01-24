
use sha2::{Digest, Sha256};
use sha2::digest::Update;

use crate::lib::components::fors::public::ForsSignature;
use crate::lib::components::merkle_tree::secret::pair_keys;
use crate::lib::helpers::hasher::{HashContext};
use crate::lib::helpers::random_generator::{Address, HashData, InnerKeyRole, get_key};

pub struct Fors<const K: usize, const A: usize> {
    seed: HashData,
    context: HashContext,
}

impl<const K: usize, const A: usize> Fors<K, A> {
    // A means the HEIGHT of the tree, as suggested in FIPS 205
    pub fn new(seed: HashData, context: HashContext) -> Self {
        Self { seed, context }
    }

    pub fn message_to_indices(message: &[u8]) -> [u32; K] {
        let mut indices = [0u32;K];
        
        for i in 0..K {
            let offset_bits = i * A;
            let bit_idx = offset_bits % 8;
            let byte_idx = offset_bits / 8;

            let b0 = *(message.get(byte_idx)).unwrap_or(&0) as u32; 
            let b1 = *(message.get(byte_idx + 1)).unwrap_or(&0) as u32; 
            let b2 = *(message.get(byte_idx + 2)).unwrap_or(&0) as u32; 

            let super_byte = (b0 << 16) | (b1 << 8) | b2; // 24 bits of the message converted

            let shift = 24 - (bit_idx + A);
            let mask = (1 << A) - 1;
            let index = (super_byte >> shift) & mask;
            indices[i]=index;
        };
        indices
    }
    fn generate_pseoudo_random_keys(&self, position: u64, keys_to_create: usize) -> Vec<HashData> {
            let mut keys: Vec<HashData> = vec!();
            
            for j in 0..keys_to_create {
                let key = get_key(self.seed, &Address{level: 0, position}, &InnerKeyRole::Fors, j);
                keys.push(key);
            };
            keys
    }
    pub fn generate_public_key(&self) -> HashData {
        let mut roots = Sha256::new();

        let keys_to_create = (2 as usize).pow(A as u32);
        for i in 0..K {
            let mut keys = self.generate_pseoudo_random_keys(i as u64, keys_to_create);
            for _ in 0..A {
                keys = pair_keys(&keys, self.context.public_seed);
            }

            Update::update(&mut roots, &keys[0])
        };
        roots.finalize().into()
        
    }
    pub fn sign(&self, message: &[u8]) -> ForsSignature<K, A>{
        todo!()
    }
    fn get_auth_path(&self, tree_idx: usize, leaf_idx: u32) -> [HashData; A] {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use crate::lib::{components::wots_plus::signature, helpers::{hasher::hash_message, random_generator::HASH_DATA_0}};

    use super::*;
    #[test]
    fn test_message_to_indices_all_0() {
        let message = [0u8; 202];

        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0u32; 10]);

        let message = [0u8; 1];

        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0u32; 10]);
    }

    #[test]
    fn test_message_to_indices_all_1() {
        let message = [0xFFu8; 202];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0x3FFF; 10]);
        
        let message = [0xFFu8; 1];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        let expected = [0x3FC0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(indices, expected);
    }
    
    #[test]
    fn test_message_to_indices_mixed() {
        let message = [0xAAu8; 202];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0x2AAAu32; 10]);

        let message = [0xAAu8; 1];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0x2A80, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let message = [0xAAu8, 0xFFu8, 0xBBu8, 0x00u8];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [10943, 15280, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_get_public_key() {
        let fors1:Fors<4, 8> = Fors::new(hash_message("Hello".as_bytes()), HashContext { public_seed: hash_message("Bye".as_bytes()), 
            address: Address { level: 0, position: 0 }});
        let pubk1 = fors1.generate_public_key();

        let fors2:Fors<4, 8> = Fors::new(hash_message("Hello".as_bytes()), HashContext { public_seed: hash_message("Bye".as_bytes()), 
            address: Address { level: 0, position: 0 }});
        let pubk2 = fors2.generate_public_key();

        let fors3:Fors<4, 8> = Fors::new(hash_message("HellO".as_bytes()), HashContext { public_seed: hash_message("Bye".as_bytes()), 
            address: Address { level: 0, position: 0 }});
        let pubk3 = fors3.generate_public_key();

        let fors4:Fors<4, 8> = Fors::new(hash_message("HellO".as_bytes()), HashContext { public_seed: hash_message("ByE".as_bytes()), 
            address: Address { level: 0, position: 0 }});
        let pubk4 = fors4.generate_public_key();

        assert_eq!(pubk1, pubk2);
        assert_ne!(pubk1, pubk3);
        assert_ne!(pubk3, pubk4);

    }

    #[test]
    fn test_sign_basic_integrity() {
        let fors: Fors<4, 4> = Fors::new(HASH_DATA_0, HashContext { public_seed: HASH_DATA_0, address: Address::default() });
        let expected_keys_tree_0 = fors.generate_pseoudo_random_keys(0, 16); // 16 = 2^4
        let signature = fors.sign(&HASH_DATA_0);

        assert_eq!(signature.signatures[0].secret_key, expected_keys_tree_0[0]);
        assert_eq!(signature.signatures[0].auth_path[0], expected_keys_tree_0[1]);
        
    }
}