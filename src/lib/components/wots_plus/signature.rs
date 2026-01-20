use sha2::{Digest, Sha256, digest::Update};
use crate::lib::helpers::{hasher::{HashContext, complement_hash, hash_vector}, random_generator::HashData};

pub const MAX_HASHES_NEEDED:u16 = 255 * 32;

#[derive(Debug,Clone, PartialEq)]
pub struct WotsPlusSignature {
    pub context: HashContext,
    pub message_hashes: [HashData;32],
    pub checksum_hashes: [HashData;2],
}

impl<'a> WotsPlusSignature {
    pub fn get_expected_public_from_hash(self, message_hash: &HashData) -> HashData {
        let mut count_hashes_left: u16 = MAX_HASHES_NEEDED;
        let mut out = [[0u8;32];34];

        for (index, times_repeated) in message_hash.into_iter().enumerate() {
            let key = self.message_hashes[index];
            out[index] = complement_hash(key, times_repeated.clone(), &self.context);
            count_hashes_left -= times_repeated.clone() as u16; 
        };
        
        let two_bytes = count_hashes_left.to_le_bytes();

        for (index, times_to_repeat) in two_bytes.into_iter().enumerate() {
            let key = self.checksum_hashes[index];
            out[32 + index] = complement_hash(key, times_to_repeat.clone(), &self.context);
        };

        hash_vector(&out)
    }

    pub fn get_expected_public_from_message(&self, message:&[u8]) -> HashData {
        let mut message_hash = Sha256::default();
        Update::update(&mut message_hash, message);
        self.clone().get_expected_public_from_hash(&message_hash.finalize().into())
    }
    pub fn to_bytes(&self) -> [u8; 42] {
        todo!()
    }
    
    pub fn from_bytes(_bytes: [u8; 42]) -> Self{
        todo!()
    }
}
#[cfg(test)]
mod tests {
    use crate::lib::{components::wots_plus::{secret::WotsPlus, signature::WotsPlusSignature}, helpers::{hasher::HashContext, random_generator::Address}};

    #[test]
    fn test_to_from_bytes() {
        const MESSAGE:&[u8] = "Hello from rust sphincs".as_bytes();

        let context = HashContext{public_seed: [2u8;32], address: Address{level: 2, position: 11}};
        let other_context = HashContext{public_seed: [2u8;32], address: Address{level: 2, position: 11}};
        
        let wots1 = WotsPlus::new([9u8;32], context.clone());
        let wots2 = WotsPlus::new([7u8;32], context.clone());
        let wots_other = WotsPlus::new([9u8;32], other_context);

        let signature1 = wots1.sign_message(MESSAGE);
        let signature2 = wots2.sign_message(MESSAGE);
        let signature_other = wots_other.sign_message(MESSAGE);

        let bytes_sign1 = signature1.to_bytes();

        let sign_from_bytes = WotsPlusSignature::from_bytes(bytes_sign1);

        assert_eq!(signature1, sign_from_bytes);
        assert_ne!(sign_from_bytes.message_hashes, signature2.message_hashes);
        assert_ne!(sign_from_bytes.message_hashes, signature_other.message_hashes);
    
        let pub1 = signature1.get_expected_public_from_message(MESSAGE);
        let pub_bytes = sign_from_bytes.get_expected_public_from_message(MESSAGE);
        
        assert_eq!(pub1, pub_bytes);

    }
}