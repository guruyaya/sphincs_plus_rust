use crate::lib::helpers::random_generator::HashData;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForsSignatureElement<const A: usize> {
    pub secret_key: HashData,
    pub auth_path: [HashData; A],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForsSignature<const K: usize, const A: usize> {
    pub signatures: [ForsSignatureElement<A>; K],
}