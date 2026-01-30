use crate::lib::{
    components::sphincs::secret::SphincsSigner,
    helpers::hasher::hash_message
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
    assert_ne!(signature1.hyper_tree.proofs[0].signature.context.address, signature2.hyper_tree.proofs[0].signature.context.address);
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

#[test]
fn test_timestamp_effect() {
    const K: usize = 4;
    const A: usize = 4;
    const LAYERS: usize = 2;
    const TREE_HEIGHT: usize = 3;

    let seed = hash_message("my secret seed".as_bytes());
    let public_seed = hash_message("my public seed".as_bytes());
    let signer = SphincsSigner::<K, A, LAYERS, TREE_HEIGHT>::new(seed, public_seed);

    let message = b"Same message, different time";

    // חתימה בזמן T
    let timestamp1 = 1000;
    let sig1 = signer.sign_with_set_ts(message, timestamp1, None);

    // חתימה בזמן T + 1
    let timestamp2 = 2000;
    let sig2 = signer.sign_with_set_ts(message, timestamp2, None);

    // 1. ווידוא שה-timestamp נשמר נכון בחתימה
    assert_eq!(sig1.timestamp, timestamp1);
    assert_eq!(sig2.timestamp, timestamp2);

    // 2. ווידוא שהחתימות שונות לגמרי (בגלל שהאינדקס השתנה)
    // ה-FORS אמור לבחור עלים שונים לגמרי
    assert_ne!(sig1.fors.signatures, sig2.fors.signatures);
    
    // 3. ווידוא שהחתימה הכוללת שונה
    assert_ne!(sig1, sig2);
}