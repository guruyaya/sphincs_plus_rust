
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

    pub fn hash_vector(hashes: &[ [u8; 32] ]) -> [u8; 32]{
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use rand;
    use super::hasher::*;
    use super::super::random_generator::RandomGenerator64;

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

    // #[test]
    // fn test_hash_vector() {
    //     let generator = RandomGenerator64::new([3;32]);
    // }

}