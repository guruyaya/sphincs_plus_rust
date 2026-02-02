use std::time::{SystemTime, UNIX_EPOCH};

use crate::lib::components::fors::public::ForsSignature;
use crate::lib::components::{fors::secret::Fors, hypertree::secret::HyperTreeSigner};
use crate::lib::helpers::hasher::{HashContext, hash_array, hash_message};
use crate::lib::helpers::random_generator::Address;
use crate::lib::{helpers::random_generator::HashData};
use crate::lib::components::sphincs::{signature::SphincsSignature,public::{KeyParams, SphincsPublic}};

pub fn get_ms_timestamp_milliseconds() -> u128{
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("time should go forward");
    since_the_epoch.as_millis()
}

fn hash_to_u128(hash: HashData) -> u128 {
    let mut result = 0u128;
    for i in 0..2 {
        let start = i * 16;
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[start..start+16]);
        result ^= u128::from_be_bytes(bytes);
    }
    result
}

#[derive(Debug, Clone)]
pub struct SphincsSigner<const K:usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> {
    seed: HashData,
    public_seed: HashData
}
impl<const K:usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> SphincsSigner<K, A, LAYERS, TREE_HEIGHT> {
    pub fn new(seed: HashData, public_seed: HashData) -> Self {
        Self{seed, public_seed}
    }

    pub fn public_key(&self) -> SphincsPublic<K, A, LAYERS, TREE_HEIGHT> {
        let hypertree = HyperTreeSigner::<LAYERS, TREE_HEIGHT>::new(self.seed, self.public_seed);
        SphincsPublic::<K, A, LAYERS, TREE_HEIGHT>{
            key: hypertree.generate_master_public_key(),
            public_seed: self.public_seed
        }
    }
    pub fn sign_position(&self, data_hash: HashData, position: u128) -> (ForsSignature<K, A>, HashData){
        let context = HashContext{public_seed: self.public_seed, address: Address{level: 0, position: position as u128}};

        let fors = Fors::<K, A>::new(self.seed, context);
        
        (fors.sign(&data_hash), fors.generate_public_key())
    }

    pub(super) fn sign_with_set_ts(&self, message: &[u8], timestamp: u128, force_index: Option<u64>) -> SphincsSignature<K, A, LAYERS, TREE_HEIGHT> {
        let hashed_ts = hash_message(&timestamp.to_be_bytes());
        let message_hash = hash_message(message);
        let hash_and_ts = hash_array(&[message_hash, hashed_ts]);
        let max_index = (2_u128).pow(LAYERS as u32 * TREE_HEIGHT as u32);

        
        let index = match force_index {
            None => hash_to_u128(hash_and_ts) % max_index,
            Some(idx) => (idx as u128) % max_index
        };
        
        let (fors, fors_public_key) = self.sign_position(hash_and_ts, index);
        let hp_signer = HyperTreeSigner::<LAYERS, TREE_HEIGHT>::new(self.seed, self.public_seed);
        let hp_signature = hp_signer.sign(fors_public_key, index as u128);
        SphincsSignature::<K, A, LAYERS, TREE_HEIGHT>{data_hash: message_hash, fors, hyper_tree: hp_signature, timestamp: timestamp}
    }

    pub fn sign(&self, message: &[u8]) -> SphincsSignature<K, A, LAYERS, TREE_HEIGHT> {
        let timestamp = get_ms_timestamp_milliseconds();
        // self.sign_with_set_ts(message, timestamp, None)
        self.sign_with_set_ts(message, timestamp, None)
    }
}

impl<const K:usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> SphincsSigner<K, A, LAYERS, TREE_HEIGHT> {
    pub fn get_params(self) -> KeyParams {
        KeyParams { K, A, LAYERS, TREE_HEIGHT }
    }
}
