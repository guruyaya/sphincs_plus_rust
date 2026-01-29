use crate::lib::{
    components::sphincs::{secret::SphincsSigner, signature::SphincsSignature, public::SphincsPublic},
    helpers::{hasher::hash_message, random_generator::HashData}
};

#[test]
fn test_basic_signing() {
    // פרמטרים סטנדרטיים לספינקס (קטנים לבדיקה)
    const K: usize = 4;      // מספר עצי FORS
    const A: usize = 4;      // מספר ביטים לאינדקס ב-FORS
    const LAYERS: usize = 2; // מספר שכבות ב-HyperTree
    const TREE_HEIGHT: usize = 3; // גובה כל עץ ב-HyperTree
    
    // יצירת מפתח פרטי
    let seed = hash_message("my secret seed".as_bytes());
    let public_seed = hash_message("my public seed".as_bytes());
    let signer = SphincsSigner::<K, A, LAYERS, TREE_HEIGHT>::new(seed, public_seed);
    
    // הודעה לחתימה
    let message = b"Hello, SPHINCS+!";
    
    // חתימה על ההודעה
    let signature = signer.sign(message);
    
    // בדיקות בסיסיות
    assert_eq!(signature.data_hash, hash_message(message));
    assert_eq!(signature.fors.signatures.len(), K); // בדיקה שיש K חתימות FORS
    assert_eq!(signature.hyper_tree.proofs.len(), LAYERS); // בדיקה שיש LAYERS הוכחות
}

#[test]
fn test_different_messages_different_signatures() {
    const K: usize = 4;
    const A: usize = 4;
    const LAYERS: usize = 2;
    const TREE_HEIGHT: usize = 3;
    
    let seed = hash_message("my secret seed".as_bytes());
    let public_seed = hash_message("my public seed".as_bytes());
    let signer = SphincsSigner::<K, A, LAYERS, TREE_HEIGHT>::new(seed, public_seed);
    
    let message1 = b"Hello, SPHINCS+!";
    let message2 = b"Hello, SPHINCS+?";
    
    let signature1 = signer.sign(message1);
    let signature2 = signer.sign(message2);
    
    // החתימות צריכות להיות שונות
    assert_ne!(signature1, signature2);
}

#[test]
fn test_different_seeds_different_signatures() {
    const K: usize = 4;
    const A: usize = 4;
    const LAYERS: usize = 2;
    const TREE_HEIGHT: usize = 3;
    
    let seed1 = hash_message("my secret seed".as_bytes());
    let seed2 = hash_message("my other secret seed".as_bytes());
    let public_seed = hash_message("my public seed".as_bytes());
    
    let signer1 = SphincsSigner::<K, A, LAYERS, TREE_HEIGHT>::new(seed1, public_seed);
    let signer2 = SphincsSigner::<K, A, LAYERS, TREE_HEIGHT>::new(seed2, public_seed);
    
    let message = b"Hello, SPHINCS+!";
    
    let signature1 = signer1.sign(message);
    let signature2 = signer2.sign(message);
    
    // החתימות צריכות להיות שונות
    assert_ne!(signature1, signature2);
}

#[test]
fn test_public_key_generation() {
    const K: usize = 4;
    const A: usize = 4;
    const LAYERS: usize = 2;
    const TREE_HEIGHT: usize = 3;
    
    let seed = hash_message("my secret seed".as_bytes());
    let public_seed = hash_message("my public seed".as_bytes());
    let signer = SphincsSigner::<K, A, LAYERS, TREE_HEIGHT>::new(seed, public_seed);
    
    // יצירת מפתח ציבורי
    let public_key = signer.public_key();
    
    let public_key_params = &public_key.get_params();
    // בדיקות בסיסיות
    assert_eq!(public_key.public_seed, public_seed);
    assert_eq!(public_key_params.LAYERS, LAYERS);
    assert_eq!(public_key_params.TREE_HEIGHT, TREE_HEIGHT);
    assert_eq!(public_key_params.K, K);
    assert_eq!(public_key_params.A, A);
    assert_ne!(public_key.key, [0u8; 32]); // המפתח לא אמור להיות אפס
}