use crate::lib::{components::wots_plus::signature::{WotsPlusSignature, MAX_HASHES_NEEDED}, 
    helpers::{hasher::{HashContext, hash_vector, repeat_hash}, 
    random_generator::{Address, HashData, InnerKeyRole, RandomGeneratorSha256}}};
use rand;
use sha2::{Digest, Sha256, digest::Update};
use super::public::WotsPlusPublic;
pub struct SeedPair(pub HashData, pub HashData); // private_seed, public_seed


#[derive(Debug, PartialEq, Clone)]
pub struct SecretKeysPair{
    message: [HashData;32],
    checksum: [HashData;2]
}

#[derive(Debug, PartialEq)]
pub struct WotsPlus {
    seed: HashData,
    
    secret_keys: SecretKeysPair,
    pub context: HashContext
}

impl WotsPlus {
    
    pub fn gen_true_random_keys() -> SeedPair{
        SeedPair(rand::random(), rand::random())
    }

    fn generate_secret_keys(seed: HashData, address: &Address) -> SecretKeysPair{
        let mut rndgen = RandomGeneratorSha256::new(seed);
        let message_keys = rndgen.get_keys::<32>(&address, InnerKeyRole::MessageKey);
        let checksum_keys = rndgen.get_keys::<2>(&address, InnerKeyRole::ChecksumKey);
        
        SecretKeysPair {
            message: message_keys,
            checksum: checksum_keys
        }

    }

    pub fn new(seed: HashData, context: HashContext) -> Self {
        Self {seed: seed, secret_keys: Self::generate_secret_keys(seed, &context.1), context: context}
    }

    pub fn new_random(address: Address) -> Self {
        let SeedPair(seed, public_seed) = Self::gen_true_random_keys();
        Self::new(seed, HashContext(public_seed, address.clone()))
    }

    pub fn generate_public_key(&self) -> WotsPlusPublic {
        let mut public_keyset = [[0u8;32];34];
        
        for (index, sk) in self.secret_keys.message.iter().enumerate(){
            public_keyset[index] = repeat_hash(*sk, 255, &self.context);
        };
        
        for (index, sk) in self.secret_keys.checksum.iter().enumerate(){
            public_keyset[32 + index] = repeat_hash(*sk, 255, &self.context);
        };

        let public_key = hash_vector(&public_keyset);
        WotsPlusPublic { public_key: public_key, context: self.context.clone()}
    }
    
    pub fn sign_hash(&self, _hash: HashData) -> WotsPlusSignature {
        let mut count_hashes_left: u16 = MAX_HASHES_NEEDED;
        let mut message_hashes = [[0u8;32]; 32];
        let mut checksum_hashes = [[0u8;32]; 2];
        
        for (index, times_to_repeat) in _hash.into_iter().enumerate() {
            let key = self.secret_keys.message[index];
            message_hashes[index] = repeat_hash(key, times_to_repeat, &self.context);
            count_hashes_left = count_hashes_left - times_to_repeat as u16; 
        };
        dbg!("Times left secret {}", count_hashes_left);
        let two_bytes = count_hashes_left.to_le_bytes();
        for (index, times_to_repeat) in two_bytes.into_iter().enumerate() {
            let key = self.secret_keys.checksum[index];
            checksum_hashes[index] = repeat_hash(key, times_to_repeat.clone(), &self.context);
        };
        return WotsPlusSignature {checksum_hashes: checksum_hashes, context: self.context.clone(), message_hashes: message_hashes}
    }
    
    pub fn sign_message(&self, _message: &[u8]) -> WotsPlusSignature {
       let mut message_hush = Sha256::default();
       Update::update(&mut message_hush, _message);

       self.sign_hash(message_hush.finalize().into())
    }
    
    pub fn to_bytes(&self) -> [u8; 74] {
        let mut out = [0u8;74];
        out[..32].copy_from_slice(&self.seed);
        out[32..].copy_from_slice(&self.context.to_bytes());

        out
    }
    
    pub fn from_bytes(bytes: [u8; 74]) -> Self{
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use crate::lib::helpers::{hasher::HashContext, random_generator::Address};

    use super::WotsPlus;

    #[test]
    fn test_to_from_bytes() {
        let wots = WotsPlus::new([9u8;32], HashContext([10u8;32], Address{level: 1, position: 1}));
        let other_wots = WotsPlus::new([7u8;32], HashContext([90u8;32], Address{level: 2, position: 1}));
        
        let bytes_wots = wots.to_bytes();
        let bytes_other_wots = other_wots.to_bytes();

        let new_wots = WotsPlus::from_bytes(bytes_wots);
        let new_other_wots = WotsPlus::from_bytes(bytes_other_wots);

        assert_eq!(wots, new_wots);
        assert_ne!(wots, new_other_wots);
    }
}
