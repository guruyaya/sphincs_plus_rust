
pub mod hasher {
    use sha2::{Sha256, Digest, digest::Update};
    
    pub fn repeat_hash(to_hash: [u8; 32], times_to_repeat: u8) -> [u8;32] {
        let hash_step = to_hash.clone();
        (0..times_to_repeat).fold(hash_step, |acc, _| {
            let mut hashed = Sha256::default();
            Update::update(&mut hashed, &acc);
            hashed.finalize().into()
        })
    }

    pub fn complement_hash(to_hash: [u8; 32], times_repeated: u8) -> [u8;32] {
        return repeat_hash(to_hash, 255-times_repeated)
    }

    pub fn hash_vector(hashes: &Vec<[u8; 32]>) -> [u8; 32]{
        let mut hasher = Sha256::default();
        hashes.iter().for_each(|h| Update::update(&mut hasher, h));
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use rand;
    use super::hasher::*;
    use crate::lib::helpers::random_generator::{RandomGenerator64, RandomGeneratorTrait, Address};

    #[test]
    fn test_repeated_hash_same_when_zero(){
        let initial_random:  [u8;32] = rand::random();
        let hashed_random = repeat_hash(initial_random, 0);
        
        assert_eq!(initial_random, hashed_random);
    }
    
    #[test]
    fn test_complement(){
        let initial_random:  [u8;32] = [0;32];

        let hashed_random = repeat_hash(initial_random, 2);
        let simulated_complete = complement_hash(initial_random, 253);

        assert_ne!(initial_random, hashed_random);
        assert_eq!(hashed_random, simulated_complete);
    }
    
    #[test]
    fn test_target(){
        let initial_random:  [u8;32] = [0;32];

        let target_hash = repeat_hash(initial_random, 255);
        let hashed_random = repeat_hash(initial_random, 2);
        let hashed_to_taget = complement_hash(hashed_random, 2);

        assert_ne!(initial_random, hashed_random);
        assert_eq!(target_hash, hashed_to_taget);
    }

    #[test]
    fn test_hash_vector() {
        let mut generator = RandomGenerator64::new([3;32]);
        let hashes = generator.get_keys(4, Address{level: 3, position: 9});
        let out1 = hash_vector(&hashes);
        
        let new_hashes = vec![ hashes[1], hashes[0], hashes[2], hashes[3], ];
        let out2 = hash_vector(&new_hashes);
        
        assert_ne!(out1, out2);
        
        let old_hash_back = vec![ new_hashes[1], new_hashes[0], new_hashes[2], new_hashes[3], ];
        let out3 = hash_vector(&old_hash_back);
        
        assert_eq!(out3, out1);
    }

}