use crate::lib::{helpers::random_generator::HashData};

#[allow(non_snake_case)]
pub struct KeyParams {
    pub K: usize,
    pub A: usize,
    pub LAYERS: usize,
    pub TREE_HEIGHT: usize
}

pub struct SphincsPublic<const K:usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> {
    pub key: HashData,
    pub public_seed: HashData,
}

impl<const K:usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> SphincsPublic<K, A, LAYERS, TREE_HEIGHT> {
    pub fn get_params(&self) -> KeyParams {
        KeyParams { K, A, LAYERS, TREE_HEIGHT }
    }
}
