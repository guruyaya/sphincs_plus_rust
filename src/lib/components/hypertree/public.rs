use crate::lib::{components::merkle_tree::proof::MerkleProof};

#[derive(Clone, PartialEq, Debug)]
pub struct HyperTreeSignature<const LAYERS: usize, const TREE_HEIGHT: usize> {
    pub proofs: [MerkleProof<TREE_HEIGHT>; LAYERS]
}
