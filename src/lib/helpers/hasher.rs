use sha2::{Sha256, Digest, digest::Update};

use crate::lib::helpers::random_generator::{Address, HashData};

#[derive(Debug)]
pub struct HashContext<'a>(pub HashData, pub &'a Address);

impl<'a> HashContext<'a>{
    fn to_bytes(&self) -> [u8;42] {
        let mut out = [0u8;42];
        out[..32].copy_from_slice(&self.0);
        out[32..].copy_from_slice(&self.1.to_bytes());
        out
    }
}
pub fn repeat_hash(to_hash: HashData, times_to_repeat: u8, context: &HashContext) -> [u8;32] {
    let hash_step = to_hash.clone();
    (0..times_to_repeat).fold(hash_step, |acc, _| {
        let mut hashed = Sha256::default();
        
        Update::update(&mut hashed, &acc);
        Update::update(&mut hashed, &context.to_bytes());
        
        hashed.finalize().into()
    })
}

pub fn complement_hash(to_hash: HashData, times_repeated: u8, context: &HashContext) -> [u8;32] {
    return repeat_hash(to_hash, 255-times_repeated, &context)
}

pub fn hash_vector(hashes: &[HashData]) -> HashData{
    let mut hasher = Sha256::default();
    hashes.iter().for_each(|h| Update::update(&mut hasher, h));
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use rand;
    use super::*;
    use crate::lib::helpers::random_generator::{Address, InnerKeyRole, RandomGeneratorSha256};
    
    #[test]
    fn test_repeated_hash_same_when_zero(){
        let initial_random:  [u8;32] = rand::random();
        let context = HashContext([8;32], &Address { level: 10, position: 15 });
        let hashed_random = repeat_hash(initial_random, 0, &context);
        
        assert_eq!(initial_random, hashed_random);
    }
    
    #[test]
    fn test_complement(){
        let initial_random:  [u8;32] = [0;32];
        let context = HashContext([8;32], &Address { level: 10, position: 15 });
        
        let hashed_random = repeat_hash(initial_random, 2, &context);
        let simulated_complete = complement_hash(initial_random, 253, &context);
        
        assert_ne!(initial_random, hashed_random);
        assert_eq!(hashed_random, simulated_complete);
    }
    
    #[test]
    fn test_to_target(){
        let initial_random:  [u8;32] = [0;32];
        let context = HashContext([8;32], &Address { level: 10, position: 15 });
        
        let hashed_random1 = repeat_hash(initial_random, 2, &context);
        let simulated_complete1 = complement_hash(hashed_random1, 2, &context);
        
        let hashed_random2 = repeat_hash(initial_random, 10, &context);
        let simulated_complete2 = complement_hash(hashed_random2, 10, &context);
        
        assert_ne!(hashed_random2, hashed_random1);
        assert_eq!(simulated_complete1, simulated_complete2);
    }
    
    #[test]
    fn test_target(){
        let initial_random:  [u8;32] = [0;32];
        let context = HashContext([8;32], &Address { level: 10, position: 15 });
        
        let target_hash = repeat_hash(initial_random, 255, &context);
        let hashed_random = repeat_hash(initial_random, 2, &context);
        let hashed_to_taget = complement_hash(hashed_random, 2, &context);
        
        assert_ne!(initial_random, hashed_random);
        assert_eq!(target_hash, hashed_to_taget);
    }
    
    #[test]
    fn test_hash_vector() {
        let mut generator = RandomGeneratorSha256::new([3;32]);
        let hashes = generator.get_keys::<4>(&Address{level: 3, position: 9}, InnerKeyRole::MessageKey);
        let out1 = hash_vector(&hashes);
        
        let new_hashes = vec![ hashes[1], hashes[0], hashes[2], hashes[3], ];
        let out2 = hash_vector(&new_hashes);
        
        assert_ne!(out1, out2);
        
        let old_hash_back = vec![ new_hashes[1], new_hashes[0], new_hashes[2], new_hashes[3], ];
        let out3 = hash_vector(&old_hash_back);
        
        assert_eq!(out3, out1);
    }
    
    #[test]
    fn test_change_vector_seed() {
        let mut random_initial = RandomGeneratorSha256::new([3;32]);
        
        let address = &Address { level: 10, position: 15 };
        let to_hash = random_initial.get_keys::<1>(&address, InnerKeyRole::MessageKey)[0];
        let to_hash_clone = to_hash.clone();
        
        let context1 = HashContext([8;32], &address);
        let repeat1 = repeat_hash(to_hash, 5, &context1);
        
        let context2 = HashContext([9;32], &address);
        let repeat2 = repeat_hash(to_hash, 5, &context2);
        
        assert_eq!(to_hash, to_hash_clone);
        assert_ne!(repeat1, repeat2);
    }
    
    #[test]
    fn test_change_vector_position() {
        let mut random_initial = RandomGeneratorSha256::new([3;32]);
        
        let address1 = &Address { level: 10, position: 15 };
        let address2 = &Address { level: 10, position: 16 };
        let to_hash = random_initial.get_keys::<1>(&address1, InnerKeyRole::MessageKey)[0];
        let to_hash_clone = to_hash.clone();
        
        let context1 = HashContext([8;32], &address1);
        let repeat1 = repeat_hash(to_hash, 5, &context1);
        
        let context2 = HashContext([8;32], &address2);
        let repeat2 = repeat_hash(to_hash, 5, &context2);
        
        assert_eq!(to_hash, to_hash_clone);
        assert_ne!(repeat1, repeat2);

    }

    #[test]
    fn test_change_vector_level() {
        let mut random_initial = RandomGeneratorSha256::new([3;32]);
        
        let address1 = &Address { level: 10, position: 15 };
        let address2 = &Address { level: 11, position: 15 };
        let to_hash = random_initial.get_keys::<1>(address1, InnerKeyRole::MessageKey)[0];
        let to_hash_clone = to_hash.clone();
        
        let context1 = HashContext([8;32], &address1);
        let repeat1 = repeat_hash(to_hash, 5, &context1);
        
        let context2 = HashContext([9;32], &address2);
        let repeat2 = repeat_hash(to_hash, 5, &context2);
        
        assert_eq!(to_hash, to_hash_clone);
        assert_ne!(repeat1, repeat2);

    }

    #[test]
    fn test_same_vector_address_and_seed() {
        let mut random_initial = RandomGeneratorSha256::new([3;32]);
        
        let address1 = &Address { level: 10, position: 15 };
        let address2 = &Address { level: 10, position: 15 };

        let to_hash = random_initial.get_keys::<1>(address1, InnerKeyRole::MessageKey)[0];
        let to_hash_clone = to_hash.clone();
        
        let context1 = HashContext([8;32], &address1);
        let repeat1 = repeat_hash(to_hash, 5, &context1);
        
        let context2 = HashContext([8;32], &address2);
        let repeat2 = repeat_hash(to_hash, 5, &context2);
        
        assert_eq!(to_hash, to_hash_clone);
        assert_eq!(repeat1, repeat2);

    }
    
}