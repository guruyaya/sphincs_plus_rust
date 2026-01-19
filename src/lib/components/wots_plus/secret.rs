use crate::lib::{components::wots_plus::signature::WotsPlusSignature, 
    helpers::{hasher::{HashContext, hash_vector, repeat_hash}, 
    random_generator::{Address, HashData, InnerKeyRole, RandomGeneratorSha256}}};
use rand;
use super::public::WotsPlusPublic;
pub(super) struct SeedPair(pub HashData, pub HashData); // private_seed, public_seed


#[derive(Debug)]
pub struct SecretKeysPair{
    message: [HashData;32],
    checksum: [HashData;2]
}

#[derive(Debug)]
pub struct WotsPlus {
    seed: HashData,
    
    secret_keys: SecretKeysPair,

    pub public_seed: HashData,
    pub address: Address
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

    pub fn new(seed: HashData, public_seed: HashData, address: &Address) -> Self {
        Self {seed: seed, public_seed: public_seed, address: address.clone(), secret_keys: Self::generate_secret_keys(seed, address)}
    }

    pub fn new_random(address: Address) -> Self {
        let SeedPair(seed, public_seed) = Self::gen_true_random_keys();
        Self::new(seed, public_seed, &address)
    }

    pub fn generate_public_key(&self) -> WotsPlusPublic<'_> {
        let mut public_keyset = [[0u8;32];34];
        let context = HashContext(self.public_seed, &self.address);

        for (index, k) in self.secret_keys.message.iter().enumerate(){
            public_keyset[index] = repeat_hash(*k, 255, &context);
        };
        
        for (index, k) in self.secret_keys.checksum.iter().enumerate(){
            public_keyset[32 + index] = repeat_hash(*k, 255, &context);
        };

        let public_key = hash_vector(&public_keyset);
        WotsPlusPublic { start_address: &self.address, public_seed: self.public_seed, public_key: public_key}
    }
    
    pub fn sign_hash(&self, _hash: HashData) -> WotsPlusSignature {
        todo!()
    }
    
    pub fn sign_message(&self, _message: &[u8]) -> WotsPlusSignature {
       todo!();
    }
    
    pub fn to_bytes(&self) -> [u8; 42] {
        todo!()
    }
    
    pub fn from_bytes(_bytes: [u8; 42]) -> Self{
        todo!()
    }
    
}
