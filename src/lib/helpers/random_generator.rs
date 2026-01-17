
use sha2::{Sha256, Digest, digest::Update};
pub type HashData = [u8;32];

#[derive(Clone, Debug)]
pub struct Address {
    pub level: u16,
    pub position: u64
}

impl Address {
    pub fn to_bytes(&self) -> [u8;10]{
        let mut out = [0u8;10];
        out[..2].copy_from_slice(&self.level.to_be_bytes());
        out[2..].copy_from_slice(&self.position.to_be_bytes());
        out
    }
}
fn get_key(seed: HashData, address: &Address) -> HashData {
    let mut hasher = Sha256::default();
    Update::update(&mut hasher, &seed);
    Update::update(&mut hasher, &address.to_bytes());
    let result = hasher.finalize();
    result.into()
}

pub trait RandomGeneratorTrait {
    fn new(seed: HashData) -> Self;
    fn get_keys(&mut self, num_keys: u64, address: &Address) -> Vec<HashData>;
}

// struct RandomGenerator32 {
//     seed: HashData,
//     counter: u32
// }

// impl RandomGeneratorTrait for RandomGenerator32 {
// }

#[derive(Clone, Debug)]
pub struct RandomGenerator64 {
    seed: HashData,
}

impl RandomGeneratorTrait for RandomGenerator64 {
    fn new(seed: HashData) -> Self {
        RandomGenerator64 { seed }
    }

    fn get_keys(&mut self, num_keys: u64, address: &Address) -> Vec<HashData> {
        (0..num_keys).into_iter().map(|i| {
            let new_address = Address {level: address.level, position: address.position + i};
            get_key(self.seed, &new_address)
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{RandomGenerator64, Address, RandomGeneratorTrait, HashData};

    #[test]
    fn test_effect_of_position() {
        let seed:HashData = [0;32];
        let mut generator = RandomGenerator64::new(seed);
        
        let address1 = Address {level: 0, position: 19};
        let key_list1 = generator.get_keys(2, &address1);
        
        assert_eq!(key_list1.len(), 2);
        assert_ne!(key_list1[0], key_list1[1]);
        
        let address2 = Address {level: 0, position: 20};
        let key_list2 = generator.get_keys(2, &address2);
        
        assert_eq!(key_list2.len(), 2);
        assert_ne!(key_list2[0], key_list2[1]);
        assert_ne!(key_list1[0], key_list2[0]);
        assert_ne!(key_list1[1], key_list2[1]);
        assert_ne!(key_list1[0], key_list2[1]);
        assert_eq!(key_list1[1], key_list2[0]);
    }

    #[test]
    fn test_effect_of_level() {
        let seed:HashData = [0;32];
        let mut generator = RandomGenerator64::new(seed);
        
        let address1 = Address {level: 0, position: 19};
        let key_list1 = generator.get_keys(2, &address1);
        
        assert_eq!(key_list1.len(), 2);
        assert_ne!(key_list1[0], key_list1[1]);
        
        let address2 = Address {level: 1, position: 19};
        let key_list2 = generator.get_keys(2, &address2);
        
        assert_eq!(key_list2.len(), 2);
        assert_ne!(key_list2[0], key_list2[1]);
        assert_ne!(key_list1[0], key_list2[0]);
        assert_ne!(key_list1[1], key_list2[1]);
        assert_ne!(key_list1[0], key_list2[1]);
        assert_ne!(key_list1[1], key_list2[0]);

    }

    #[test]
    fn test_effect_of_seed() {
        let seed1:HashData = [0;32];
        let mut generator1 = RandomGenerator64::new(seed1);
        
        let address = Address {level: 0, position: 19};
        let key_list1 = generator1.get_keys(2, &address);
        
        assert_eq!(key_list1.len(), 2);
        assert_ne!(key_list1[0], key_list1[1]);
        
        let mut seed2:HashData = [0;32];
        seed2[0] = 1;

        let mut generator2 = RandomGenerator64::new(seed2);
        let key_list2 = generator2.get_keys(2, &address);
        
        assert_eq!(key_list2.len(), 2);
        assert_ne!(key_list2[0], key_list2[1]);
        assert_ne!(key_list1[0], key_list2[0]);
        assert_ne!(key_list1[1], key_list2[1]);
        assert_ne!(key_list1[0], key_list2[1]);
        assert_ne!(key_list1[1], key_list2[0]);

    }

    #[test]
    fn test_all_the_same() {
        let seed1:HashData = [0;32];
        let mut generator1 = RandomGenerator64::new(seed1);
        
        let address = Address {level: 0, position: 19};
        let key_list1 = generator1.get_keys(2, &address);
        
        assert_eq!(key_list1.len(), 2);
        assert_ne!(key_list1[0], key_list1[1]);
        
        let seed2:HashData = [0;32];

        let mut generator2 = RandomGenerator64::new(seed2);
        let key_list2 = generator2.get_keys(2, &address);
        
        assert_eq!(key_list2.len(), 2);
        assert_ne!(key_list2[0], key_list2[1]);
        assert_eq!(key_list1[0], key_list2[0]);
        assert_eq!(key_list1[1], key_list2[1]);
    }


}