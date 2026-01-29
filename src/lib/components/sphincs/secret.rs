use crate::lib::{components::{hypertree::secret::HyperTreeSigner}};
use crate::lib::{helpers::random_generator::HashData};
use crate::lib::components::sphincs::{signature::SphincsSignature,public::{KeyParams, SphincsPublic}};

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

    pub fn sign(&self, message: &[u8]) -> SphincsSignature<K, A, LAYERS, TREE_HEIGHT> {
        todo!()
    }
}

impl<const K:usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> SphincsSigner<K, A, LAYERS, TREE_HEIGHT> {
    fn get_params(self) -> KeyParams {
        KeyParams { K, A, LAYERS, TREE_HEIGHT }
    }
}
