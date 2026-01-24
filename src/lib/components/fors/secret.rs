
use crate::lib::helpers::hasher::HashContext;
use crate::lib::helpers::random_generator::HashData;

pub struct Fors<const K: usize, const A: usize> {
    seed: HashData,
    context: HashContext,
}

impl<const K: usize, const A: usize> Fors<K, A> {
    // A means the HEIGHT of the tree, as suggested in FIPS 205
    pub fn new(seed: HashData, context: HashContext) -> Self {
        Self { seed, context }
    }

    pub fn message_to_indices(message: &[u8]) -> [u32; K] {
        let mut indices = [0u32;K];
        
        for i in 0..K {
            let offset_bits = i * A;
            let bit_idx = offset_bits % 8;
            let byte_idx = offset_bits / 8;

            let b0 = *(message.get(byte_idx)).unwrap_or(&0) as u32; 
            let b1 = *(message.get(byte_idx + 1)).unwrap_or(&0) as u32; 
            let b2 = *(message.get(byte_idx + 2)).unwrap_or(&0) as u32; 

            let super_byte = (b0 << 16) | (b1 << 8) | b2; // 24 bits of the message converted

            let shift = 24 - (bit_idx + A);
            let mask = (1 << A) - 1;
            let index = (super_byte >> shift) & mask;
            indices[i]=index;
        };
        indices
    }
}

#[cfg(test)]
mod tests {
    use super::*; // מייבא את Fors

    #[test]
    fn test_message_to_indices_all_0() {
        let message = [0u8; 202];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0u32; 10]);

        let message = [0u8; 1];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0u32; 10]);
    }

    #[test]
    fn test_message_to_indices_all_1() {
        let message = [0xFFu8; 202];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0x3FFF; 10]);
        
        let message = [0xFFu8; 1];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        let expected = [0x3FC0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(indices, expected);
    }
    
    #[test]
    fn test_message_to_indices_mixed() {
        let message = [0xAAu8; 202];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0x2AAAu32; 10]);

        let message = [0xAAu8; 1];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [0x2A80, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let message = [0xAAu8, 0xFFu8, 0xBBu8, 0x00u8];
        // אנחנו מגדירים K=1 ו-A=14 באופן מפורש
        let indices = Fors::<10, 14>::message_to_indices(&message);
        assert_eq!(indices, [10943, 15280, 0, 0, 0, 0, 0, 0, 0, 0]);
    }
}