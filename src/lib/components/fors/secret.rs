
use sha2::{Digest, Sha256};
use sha2::digest::Update;

use crate::lib::components::fors::indices::message_to_indices;
use crate::lib::components::fors::public::{ForsSignature, ForsSignatureElement};
use crate::lib::components::merkle_tree::secret::pair_keys;
use crate::lib::helpers::hasher::{HashContext, hash_message};
use crate::lib::helpers::random_generator::{HashData, InnerKeyRole, get_key};

pub struct Fors<const K: usize, const A: usize> {
    seed: HashData,
    context: HashContext,
    keys_per_tree: usize
}

impl<const K: usize, const A: usize> Fors<K, A> {
    // A means the HEIGHT of the tree, as suggested in FIPS 205
    pub fn new(seed: HashData, context: HashContext) -> Self {
        let keys_per_tree = (2_usize).pow(A as u32);
        Self { seed, context, keys_per_tree }
    }

    fn generate_pseoudo_random_keys(&self, tree_idx: u64) -> Vec<HashData> {
            let mut keys: Vec<HashData> = vec!();
            
            for j in 0..self.keys_per_tree {
                let combined_idx = (tree_idx as usize) * self.keys_per_tree + j;
                let key = get_key(self.seed, &self.context.address, &InnerKeyRole::Fors, combined_idx);
                keys.push(key);
            };
            keys
    }
    pub fn generate_public_key(&self) -> HashData {
        let mut roots = Sha256::new();

        for i in 0..K {
            let mut keys = self.generate_pseoudo_random_keys(i as u64);
            keys = keys.into_iter().map(|key| hash_message(&key)).collect();
            for _ in 0..A {
                keys = pair_keys(&keys, self.context.public_seed);
            }

            Update::update(&mut roots, &keys[0])
        };
        roots.finalize().into()
        
    }
    pub fn sign(&self, message: &[u8]) -> ForsSignature<K, A>{
        let indices = message_to_indices::<K, A>(message);
        let signatures = std::array::from_fn(|tree_idx| {
            let index = indices[tree_idx];
            let secret_keys = self.generate_pseoudo_random_keys(tree_idx as u64);
            let secret_key = secret_keys[index as usize];
            let auth_path = self.get_auth_path(&secret_keys, index);

            ForsSignatureElement{secret_key, auth_path}
        });
        ForsSignature {signatures, context: self.context.clone(), public_key: self.generate_public_key()}
    }
    pub(super)fn get_auth_path(&self, secret_keys: &[HashData], mut leaf_idx: u32) -> [HashData; A] {
        let mut keys: Vec<HashData> = secret_keys.iter().map(|key| hash_message(key)).collect();
        
        core::array::from_fn(|_| {
            let neighbor_idx = leaf_idx ^ 1;
            let ret_val = keys[neighbor_idx as usize];
            keys = pair_keys(&keys, self.context.public_seed);
            leaf_idx /= 2;
            ret_val
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::lib::helpers::{hasher::{hash_array, hash_message}, random_generator::{Address, HASH_DATA_0}};

    use super::*;
    use super::super::indices::message_to_indices;

    #[test]
    fn test_message_to_indices_all_0() {
        let message = [0u8; 202];

        let indices = message_to_indices::<10, 14>(&message);
        assert_eq!(indices, [0u32; 10]);

        let message = [0u8; 1];

        let indices = message_to_indices::<10, 14>(&message);
        assert_eq!(indices, [0u32; 10]);
    }

    #[test]
    fn test_message_to_indices_all_1() {
        let message = [0xFFu8; 202020];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = message_to_indices::<10, 14>(&message);
        assert_eq!(indices, [0x3FFF; 10]);
        
        let message = [0xFFu8; 1];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = message_to_indices::<10, 14>(&message);
        let expected = [0x3FC0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(indices, expected);
    }
    
    #[test]
    fn test_message_to_indices_real_hash() {
        let message = hash_message("This is a real world message to sign".as_bytes());
        let indices = message_to_indices::<10, 14>(&message);
        let expected = [7426, 10818, 5414, 14732, 10730, 10731, 11712, 1719, 11223, 6407];
        assert_eq!(indices, expected);
    }
    #[test]
    fn test_message_to_indices_mixed() {
        let message = [0xAAu8; 202];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = message_to_indices::<10, 14>(&message);
        assert_eq!(indices, [0x2AAAu32; 10]);

        let message = [0xAAu8; 1];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = message_to_indices::<10, 14>(&message);
        assert_eq!(indices, [0x2A80, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let message = [0xAAu8, 0xFFu8, 0xBBu8, 0x00u8];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = message_to_indices::<10, 14>(&message);
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

        // בדיקה שהוספנו: שינוי ב-Address בלבד חייב לשנות את המפתח הציבורי
        let fors5:Fors<4, 8> = Fors::new(hash_message("Hello".as_bytes()), HashContext { public_seed: hash_message("Bye".as_bytes()),
            address: Address { level: 0, position: 1 }}); // מיקום שונה
        let pubk5 = fors5.generate_public_key();
        
        // לפני התיקון, זה היה נכשל (הם היו שווים)
        assert_ne!(pubk1, pubk5);
    }

    #[test]
    fn test_sign_basic_integrity() {
        let fors: Fors<4, 4> = Fors::new(HASH_DATA_0, HashContext { public_seed: HASH_DATA_0, address: Address::default() });
        let expected_keys_tree_0 = fors.generate_pseoudo_random_keys(0);
        let signature = fors.sign(&HASH_DATA_0);

        assert_eq!(signature.signatures[0].secret_key, expected_keys_tree_0[0]);
        assert_eq!(signature.signatures[0].auth_path[0], hash_message(&expected_keys_tree_0[1]));
    }

    #[test]
    fn test_get_auth_path() {
        let ctx = HashContext { public_seed: HASH_DATA_0, address: Address::default() };
        let fors: Fors<4, 4> = Fors::new(HASH_DATA_0, ctx.clone());
        let secret_keys:Vec<HashData> = fors.generate_pseoudo_random_keys(0);
        let idx = 1;
        let auth_path = fors.get_auth_path(&secret_keys, idx);

        let mut current_hash = hash_message(&secret_keys[idx as usize]);

        for i in 0..4 {
            let sibling = auth_path[i];

            let pair = if idx % 2 == 0 {
                [current_hash, sibling]
            } else {
                [sibling, current_hash]
            };
            current_hash = hash_array(&[pair[0], pair[1], ctx.public_seed]);
        }

        assert_eq!(auth_path[0], hash_message(&secret_keys[0]));
        
        let leaf2 = hash_message(&secret_keys[2]);
        let leaf3 = hash_message(&secret_keys[3]);

        let pair = vec![leaf2, leaf3];
        assert_eq!(auth_path[1], pair_keys(&pair, ctx.public_seed)[0]);
    }
}