use crate::lib::{components::wots_plus::signature::WotsPlusSignature, helpers::{hasher::{HashContext, hash_message}, random_generator::HashData}};

#[derive(Debug, Clone, PartialEq)]
pub struct WotsPlusPublic {
    pub public_key: HashData,
    pub context: HashContext,
}


impl WotsPlusPublic {
    
    pub fn validate_hash(&self, hash: HashData, sign: &WotsPlusSignature) -> bool {
        sign.clone().get_expected_public_from_hash(&hash) == self.public_key
    }

    pub fn validate_message(&self, message: &[u8], _sign: &WotsPlusSignature) -> bool {
        let message_hash = hash_message(message);
        self.validate_hash(message_hash, _sign)
    }

    // Size: public_key (32) + public_seed (32) + address (10) = 74
    pub fn to_bytes(&self) -> [u8; 74] {
        let mut out = [0u8; 74];
        out[..32].copy_from_slice(&self.public_key);
        out[32..].copy_from_slice(&self.context.to_bytes());

        out
    }
    
    pub fn from_bytes(bytes: [u8; 74]) -> Self{
        let public_key:[u8;32] = bytes[..32].try_into().expect("Wrong size / type passed");
        let context_bytes = bytes[32..].try_into().expect("Wrong size / type passed");
        let context = HashContext::from_bytes(context_bytes);

        Self{public_key: public_key, context: context}
    }
    
}

#[cfg(test)]
mod tests {
    use crate::lib::{components::wots_plus::public::WotsPlusPublic, helpers::{hasher::HashContext, random_generator::Address}};

    #[test]
    fn test_to_from_bytes() {
        let public1 = WotsPlusPublic{public_key: [10u8;32], context: HashContext{public_seed: [4u8;32], address: Address{level: 7, position: 15}}};
        let public2 = WotsPlusPublic{public_key: [9u8;32], context: HashContext{public_seed: [17u8;32], address: Address{level: 8, position: 15}}};
    
        let bytes_public = public1.to_bytes();

        let new_re_public = WotsPlusPublic::from_bytes(bytes_public);

        assert_eq!(public1, new_re_public);
        assert_ne!(new_re_public, public2);
    }
}