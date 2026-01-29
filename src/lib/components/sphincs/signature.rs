use crate::lib::{components::{fors::{public::ForsSignature, secret::Fors}, hypertree::public::HyperTreeSignature}, helpers::random_generator::HashData};

#[derive(Debug, PartialEq)]
pub struct SphincsSignature<const K:usize, const A: usize, const LAYERS: usize, const TREE_HEIGHT: usize> {
    pub data_hash: HashData,
    pub fors: ForsSignature<K, A>,
    pub hyper_tree: HyperTreeSignature<LAYERS, TREE_HEIGHT>
}
