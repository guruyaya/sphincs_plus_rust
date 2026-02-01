use sha2::{Digest, Sha256, digest::Update};
use crate::lib::helpers::{hasher::{HashContext, complement_hash, hash_array}, random_generator::{HASH_DATA_0, HashData}};

pub const MAX_HASHES_NEEDED:u16 = 255 * 32;

#[derive(Debug,Clone, PartialEq)]
pub struct WotsPlusSignature {
    pub context: HashContext,
    pub message_hashes: [HashData;32],
    pub checksum_hashes: [HashData;2],
    pub public_key: HashData
}

impl<'a> WotsPlusSignature {
    pub fn get_expected_public_from_hash(self, message_hash: &HashData) -> HashData {
        let mut count_hashes_left: u16 = MAX_HASHES_NEEDED;
        let mut out = [HASH_DATA_0;34];

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

        hash_array(&out)
    }

    pub fn get_expected_public_from_message(&self, message:&[u8]) -> HashData {
        let mut message_hash = Sha256::default();
        Update::update(&mut message_hash, message);
        self.clone().get_expected_public_from_hash(&message_hash.finalize().into())
    }
    
    pub fn to_bytes(&self) -> [u8; 1130] {
        let mut out = [08;1130];
        out[..42].copy_from_slice(&self.context.to_bytes());

        let mut offset = 42;
        for hash in self.message_hashes {
            out[offset..offset+32].copy_from_slice(&hash);
            offset += 32;
        };
        
        for hash in self.checksum_hashes {
            out[offset..offset+32].copy_from_slice(&hash);
            offset += 32;
        };

        out
    }
    
    pub fn from_bytes(bytes: [u8; 1130]) -> Self{
        let context_bytes:[u8;42] = bytes[..42].try_into().expect("Wrong size / datatype passed");
        let context = HashContext::from_bytes(context_bytes);

        let mut message_hashes:[HashData;32] = [HASH_DATA_0;32];
        let message_hashes_part = &bytes[42..1066];
        for i in 0..32{
            message_hashes[i].copy_from_slice(&message_hashes_part[i*32..(i+1)*32]);
        }
        
        let mut checksum_hashes:[HashData;2] = [HASH_DATA_0;2];
        let checksum_hashes_part = &bytes[1066..];
        for i in 0..2{
            checksum_hashes[i].copy_from_slice(&checksum_hashes_part[i*32..(i+1)*32]);
        }
        
        Self{context: context, message_hashes: message_hashes, checksum_hashes: checksum_hashes, public_key: HASH_DATA_0}
    }
}