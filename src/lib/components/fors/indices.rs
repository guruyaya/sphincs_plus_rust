pub fn message_to_indices<const K: usize, const A: usize>(message: &[u8]) -> [u32; K] {
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