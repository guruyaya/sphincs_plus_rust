#[cfg(test)]
mod tests {
    use crate::lib::{components::wots_plus::secret::{SeedPair, WotsPlus}, helpers::random_generator::{Address, HashData, InnerKeyRole, RandomGeneratorSha256, byte_array_to_hex}};
    use std::collections::HashSet;
    
    fn gen_private_public_from_seed(address: &Address) -> SeedPair {
        let key:[u8;32] = [31u8;32];
        let mut generator = RandomGeneratorSha256::new(key);
        
        let seeds = generator.get_keys::<2>(&address, InnerKeyRole::MessageKey); // Dummy role for test
        
        SeedPair(seeds[0], seeds[1])
    }
    
    #[test]
    fn test_true_random_key_pair() {
        let mut hashset_of_seeds = HashSet::<HashData>::default();
        
        // Adding some past hashes, to see they are not repeated
        hashset_of_seeds.insert ([0u8;32]); // TODO: Acctually add some from debug data
        let basline_size = hashset_of_seeds.len();

        for i in 0..100 {
            let SeedPair(seed, public_seed) = WotsPlus::gen_true_random_keys();

            hashset_of_seeds.insert(seed);
            assert_eq!(i*2 + basline_size + 1, hashset_of_seeds.len(), "On iteration {}, seed {} repeated", i, byte_array_to_hex(&seed));
            hashset_of_seeds.insert(public_seed);
            assert_eq!(i*2 + basline_size + 2, hashset_of_seeds.len(), "On iteration {}, seed {} repeated", i, byte_array_to_hex(&public_seed));
        }
    }
    
    
    #[test]
    fn test_public_key_stability() {
        let address = Address {level: 1, position: 9000};
        let SeedPair(seed, public_seed) = gen_private_public_from_seed(&address);
        
        let secret1 = WotsPlus::new(seed, public_seed, address.clone());
        let secret2 = WotsPlus::new(seed, public_seed, address.clone());
        
        assert_eq!(secret1.generate_public_key().public_key, secret2.generate_public_key().public_key);
    }
    
    #[test]
    fn test_public_key_sensativity() {
        let address = Address {level: 1, position: 9000};
        let SeedPair(seed, public_seed) = gen_private_public_from_seed(&address);
        
        let mut address2 = address.clone();
        address2.position = 9001;
        
        let secret1 = WotsPlus::new(seed, public_seed, address.clone());
        // Knowingly providing the wrong address, for the test
        let secret2 = WotsPlus::new(seed, public_seed, address2.clone());
        
        let pub1 = secret1.generate_public_key().public_key;
        let pub2 = secret2.generate_public_key().public_key;
        
        let diff_bit = (0..32).map(|i| pub1[i] == pub2[i]).
            fold(0, |acc, num| acc + (num as i32));
            
        assert!(diff_bit <= 2);
    }

    #[test]
    fn test_signature_on_message() {
        let message = "Hello from SPHINCS+ on rust".as_bytes();
        let other_message = "Bye from SPHINCS+ on rust".as_bytes();
        
        let address = Address {level: 1, position: 9000};
        let wots = WotsPlus::new_random(address.clone());
        let public = wots.generate_public_key();
        
        let signature = wots.sign_message(&message);
        let other_signature = wots.sign_message(&other_message);
        
        let expected_pubkey1 = signature.get_expected_public_from_message(&message);
        let expected_pubkey2 = other_signature.get_expected_public_from_message(&other_message);
        
        assert_eq!(expected_pubkey2, expected_pubkey1);

        assert_eq!(public.public_key, expected_pubkey1);

        assert!(public.validate_message(message, &signature));
        assert!(public.validate_message(other_message, &other_signature));
        
        assert!(public.validate_message(other_message, &signature) == false);
    }

    // TODO: Test from bytes and to bytes
}