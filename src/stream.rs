use openssl::symm::{decrypt, Cipher};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub fn xor(bytes1: &[u8], bytes2: &[u8]) -> Result<Vec<u8>> {
    if bytes1.len() != bytes2.len() {
        return Err("Lengths must match!".into());
    }
    let mut output = Vec::with_capacity(bytes1.len());
    for i in 0..bytes1.len() {
        output.push(bytes1[i] ^ bytes2[i]);
    }
    Ok(output)
}

pub fn sliding_xor(message: &[u8], mask: &[u8]) -> Vec<u8> {
    assert!(mask.len() <= message.len());
    let mut result = Vec::with_capacity(message.len());
    for i in 0..message.len() {
        let mask_idx = i % mask.len();
        result.push(message[i] ^ mask[mask_idx]);
    }
    result
}

pub fn hamming_distance(bytes1: &[u8], bytes2: &[u8]) -> u32 {
    assert_eq!(bytes1.len(), bytes2.len());
    let mut distance = 0;
    for (b1, b2) in bytes1.iter().zip(bytes2) {
        distance += (b1 ^ b2).count_ones();
    }
    distance
}

pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    decrypt(Cipher::aes_128_ecb(), key, None, ciphertext).unwrap()
}

// ***** TESTS *****

#[test]
fn test_hamming_distance() {
    let bytes1 = "this is a test".as_bytes();
    let bytes2 = "wokka wokka!!!".as_bytes();
    let distance = hamming_distance(bytes1, bytes2);
    assert_eq!(distance, 37);
}
