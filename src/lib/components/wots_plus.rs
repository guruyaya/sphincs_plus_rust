use crate::lib::helpers::{random_generator::{Address, HashData, byte_array_to_hex}};
use log::{error, warn, info, debug};
use rand;

pub struct SeedPair(HashData, HashData); // private_seed, public_seed

#[derive(Debug)]
pub struct WotsPlusSignature {
    start_address: Address,
    public_seed: HashData,

    message_hashes: [HashData;32],
    checksum_hashes: [HashData;2],
}

impl WotsPlusSignature {
    pub fn new(start_address: Address, public_seed: HashData, message_hashes: [HashData;32], checksum_hashes: [HashData; 2]) {
        todo!();
    }
    pub fn calculate_target_key(&self) -> HashData {
        todo!()
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        todo!()
    }
    
    pub fn from_bytes(bytes: [u8; 42]) -> Self{
        todo!()
    }
}

#[derive(Debug)]
pub struct WotsPlusPublic {
    start_address: Address,
    public_seed: HashData,
    public_key: HashData
}


impl WotsPlusPublic {
    
    pub fn validate_hash(&self, hash: HashData, sign: &WotsPlusSignature) -> bool {
        todo!()
    }

    pub fn validate_message(&self, message: &[u8], sign: &WotsPlusSignature) -> bool {
        todo!()
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        todo!()
    }
    
    pub fn from_bytes(bytes: [u8; 42]) -> Self{
        todo!()
    }
    
}

#[derive(Debug)]
pub struct WotsPlus {
    seed: HashData,
    pub public_seed: HashData,
    pub address: Address
}

impl WotsPlus {
    
    pub fn gen_true_random_keys() -> SeedPair{
        SeedPair(rand::random(), rand::random())
    }

    pub fn new(seed: HashData, public_seed: HashData, address: Address) -> Self {
        Self {seed: seed, public_seed: public_seed, address: address}
    }

    pub fn new_random(address: Address) -> Self {
        let SeedPair(seed, public_seed) = Self::gen_true_random_keys();
        Self::new(seed, public_seed, address)
    }

    pub fn generate_public_key(&self) -> WotsPlusPublic {
        todo!()
    }
    
    pub fn sign_hash(&self, hash: HashData) -> WotsPlusSignature {
        todo!()
    }
    
    pub fn sign_message(&self, message: &[u8]) -> WotsPlusSignature {
       todo!();
    }
    
    pub fn to_bytes(&self) -> [u8; 42] {
        todo!()
    }
    
    pub fn from_bytes(bytes: [u8; 42]) -> Self{
        todo!()
    }
    
}
#[cfg(test)]
mod tests {
    use crate::lib::helpers::random_generator::RandomGeneratorSha256;
    use super::*;
    use std::collections::HashSet;
    
    fn gen_private_public_from_seed(address: &Address) -> SeedPair {
        let key:[u8;32] = [31u8;32];
        let mut generator = RandomGeneratorSha256::new(key);
        
        let seeds = generator.get_keys(2, &address);
        
        SeedPair(seeds[0], seeds[1])
    }
    
    #[test]
    fn test_true_random_key_pair() {
        let mut hashset_of_seeds = HashSet::<HashData>::default();
        
        // Adding some past hashes, to see they are not repeated
        hashset_of_seeds.insert ([0u8;32]); // TODO: Acctually add some from debug data
        let basline_size = hashset_of_seeds.len();

        for i in (0..100) {
            let SeedPair(seed, public_seed) = WotsPlus::gen_true_random_keys();

            hashset_of_seeds.insert(seed);
            assert_eq!(i*2 + basline_size + 1, hashset_of_seeds.len(), "On iteration {}, seed {} repeated", i, byte_array_to_hex(&seed));
            hashset_of_seeds.insert(public_seed);
            assert_eq!(i*2 + basline_size + 2, hashset_of_seeds.len(), "On iteration {}, seed {} repeated", i, byte_array_to_hex(&public_seed));
        }
    }
    
    
    #[test]
    fn test_public_key_stability() {
        let address = Address {level: 1, position: 9000};
        let SeedPair(seed, public_seed) = gen_private_public_from_seed(&address);
        
        let secret1 = WotsPlus::new(seed, public_seed, address.clone());
        let secret2 = WotsPlus::new(seed, public_seed, address);
        
        assert_eq!(secret1.generate_public_key().public_key, secret2.generate_public_key().public_key);
    }
    
    #[test]
    fn test_public_key_sensativity() {
        let address = Address {level: 1, position: 9000};
        let SeedPair(seed, public_seed) = gen_private_public_from_seed(&address);
        
        let mut address2 = address.clone();
        address2.position = 9001;
        
        let secret1 = WotsPlus::new(seed, public_seed, address);
        // Knowingly providing the wrong address, for the test
        let secret2 = WotsPlus::new(seed, public_seed, address2);
        
        let pub1 = secret1.generate_public_key().public_key;
        let pub2 = secret2.generate_public_key().public_key;
        
        let diff_bit = (0..32).map(|i| pub1[i] == pub2[i]).
            fold(0, |acc, num| acc + (num as i32));
            
        assert!(diff_bit <= 2);
    }

    #[test]
    fn test_signature_on_message() {
        let message = "Hello from SPHINCS+ on rust".as_bytes();
        
        let address = Address {level: 1, position: 9000};
        let wots = WotsPlus::new_random(address);
        let public = wots.generate_public_key();
        let signature = wots.sign_message(message);
        
        assert!(public.validate_message(message, &signature));
        
        let wrong_message = "Bye from SPHINCS+ on rust".as_bytes();
        
        assert!(public.validate_message(wrong_message, &signature) == false);
        
        let wrong_signature = wots.sign_message(wrong_message);
        
        assert!(public.validate_message(wrong_message, &wrong_signature) == false);
    }

    // TODO: Test from bytes and to bytes
}