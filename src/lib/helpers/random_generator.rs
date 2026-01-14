pub mod random_generator {
    pub struct Address {
        pub level: u16,
        pub start_key: u64
    }
    pub trait RandomGeneratorTrait {
        fn new(seed: [u8; 32]) -> Self;
        fn get_keys(&mut self, num_keys: u8, address: Address) -> Vec<[u8; 32]>;

    }

    // struct RandomGenerator32 {
    //     seed: [u8; 32],
    //     counter: u32
    // }

    // impl RandomGeneratorTrait for RandomGenerator32 {
    // }
    
    pub struct RandomGenerator64 {
        seed: [u8; 32],
    }

    impl RandomGeneratorTrait for RandomGenerator64 {
        fn new(seed: [u8; 32]) -> Self {
            RandomGenerator64 { seed }
        }

        fn get_keys(&mut self, num_keys: u8, address: Address) -> Vec<[u8; 32]> {
            todo!()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::random_generator::{RandomGenerator64, Address, RandomGeneratorTrait};

    #[test]
    fn test_number_of_diffrent_keys() {
        let address1 = Address {level: 0, start_key: 19};
        let seed:[u8;32] = [0;32];

        let mut generator = RandomGenerator64::new(seed);

        let key_list = generator.get_keys(2, address1);

        assert_eq!(key_list.len(), 2);
        assert_ne!(key_list[0], key_list[1]);
    }


}