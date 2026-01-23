
use sha2::{Sha256, Digest, digest::Update};
pub type HashData = [u8;32];
pub const HASH_DATA_0:[u8;32] = [0u8;32];

pub fn byte_array_to_hex(data: &[u8]) -> String{
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

pub enum InnerKeyRole {
    MessageKey,
    ChecksumKey
}

impl InnerKeyRole {
    fn to_bytes(&self) -> [u8;1]{
        match self {
            InnerKeyRole::ChecksumKey => {
                [1]
            }
            InnerKeyRole::MessageKey => {
                [2]
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq)]
pub struct Address {
    pub level: u16,
    pub position: u64
}

impl Address {
    pub fn to_bytes(&self) -> [u8;10]{
        let mut out = [0u8;10];
        out[..2].copy_from_slice(&self.level.to_le_bytes());
        out[2..].copy_from_slice(&self.position.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: [u8;10]) -> Self {
        let level_bytes:[u8;2] = bytes[0..2].try_into().expect("Got unexpected bites size?");
        let position_bytes:[u8; 8] = bytes[2..].try_into().expect("Got unexpected bites size?");
        let level = u16::from_le_bytes(level_bytes);
        let position = u64::from_le_bytes(position_bytes);
        
        Self{level: level, position: position}
    }
}

fn get_key(seed: HashData, address: &Address, role: &InnerKeyRole, role_pos: usize) -> HashData {
    let mut hasher = Sha256::default();
    Update::update(&mut hasher, &seed);
    Update::update(&mut hasher, &address.to_bytes());
    Update::update(&mut hasher, &role.to_bytes());
    Update::update(&mut hasher, &role_pos.to_le_bytes());

    let result = hasher.finalize();
    result.into()
}

pub trait RandomGeneratorTrait {
    fn new(seed: HashData) -> Self;
    fn get_keys(&mut self, num_keys: u16, address: &Address, role: InnerKeyRole) -> Vec<HashData>;
}

#[derive(Clone, Debug)]
pub struct RandomGeneratorSha256 {
    seed: HashData,
}

impl RandomGeneratorSha256 {
    pub fn new(seed: HashData) -> Self {
        RandomGeneratorSha256 { seed }
    }

    pub fn get_keys<const NUM_KEYS: usize>(&mut self, address: &Address, role: InnerKeyRole) -> [HashData;NUM_KEYS] {
        let mut out = [HASH_DATA_0;NUM_KEYS];
        for i in 0..NUM_KEYS {
            out[i] = get_key(self.seed, address, &role, i)
        };
        out
    }
}

#[cfg(test)]
mod tests {
    use crate::lib::helpers::random_generator::InnerKeyRole;

    use super::{RandomGeneratorSha256, Address, HashData};

    #[test]
    fn test_effect_of_position() {
        let seed:HashData = [0;32];
        let mut generator = RandomGeneratorSha256::new(seed);
        
        let address1 = Address {level: 0, position: 19};
        let key_list1 = generator.get_keys::<2>(&address1, InnerKeyRole::ChecksumKey);
        
        assert_eq!(key_list1.len(), 2);
        assert_ne!(key_list1[0], key_list1[1]);
        
        let address2 = Address {level: 0, position: 20};
        let key_list2 = generator.get_keys::<2>(&address2, InnerKeyRole::ChecksumKey);
        
        assert_eq!(key_list2.len(), 2);
        assert_ne!(key_list2[0], key_list2[1]);
        assert_ne!(key_list1[0], key_list2[0]);
        assert_ne!(key_list1[1], key_list2[1]);
        assert_ne!(key_list1[0], key_list2[1]);
    }

    #[test]
    fn test_effect_of_level() {
        let seed:HashData = [0;32];
        let mut generator = RandomGeneratorSha256::new(seed);
        
        let address1 = Address {level: 0, position: 19};
        let key_list1 = generator.get_keys::<2>(&address1, InnerKeyRole::MessageKey);
        
        assert_eq!(key_list1.len(), 2);
        assert_ne!(key_list1[0], key_list1[1]);
        
        let address2 = Address {level: 1, position: 19};
        let key_list2 = generator.get_keys::<2>(&address2, InnerKeyRole::MessageKey);
        
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
        let mut generator1 = RandomGeneratorSha256::new(seed1);
        
        let address = Address {level: 0, position: 19};
        let key_list1 = generator1.get_keys::<2>(&address, InnerKeyRole::MessageKey);
        
        assert_eq!(key_list1.len(), 2);
        assert_ne!(key_list1[0], key_list1[1]);
        
        let mut seed2:HashData = [0;32];
        seed2[0] = 1;

        let mut generator2 = RandomGeneratorSha256::new(seed2);
        let key_list2 = generator2.get_keys::<2>(&address, InnerKeyRole::MessageKey);
        
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
        let mut generator1 = RandomGeneratorSha256::new(seed1);
        
        let address = Address {level: 0, position: 19};
        let key_list1 = generator1.get_keys::<2>(&address, InnerKeyRole::MessageKey);
        
        assert_eq!(key_list1.len(), 2);
        assert_ne!(key_list1[0], key_list1[1]);
        
        let seed2:HashData = [0;32];

        let mut generator2 = RandomGeneratorSha256::new(seed2);
        let key_list2 = generator2.get_keys::<2>(&address, InnerKeyRole::MessageKey);
        
        assert_eq!(key_list2.len(), 2);
        assert_ne!(key_list2[0], key_list2[1]);
        assert_eq!(key_list1[0], key_list2[0]);
        assert_eq!(key_list1[1], key_list2[1]);
    }


}