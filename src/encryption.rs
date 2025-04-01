use openssl::symm::{decrypt, encrypt, Cipher, Crypter, Mode};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;
pub const AES128_BLOCK_SIZE: usize = 16;

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

pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    Ok(decrypt(Cipher::aes_128_ecb(), key, None, ciphertext)?)
}

pub fn encrypt_aes_ecb(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    Ok(encrypt(Cipher::aes_128_ecb(), key, None, ciphertext)?)
}

pub fn decrypt_aes_block(block: &[u8], key: &[u8]) -> Result<[u8; 16]> {
    assert_eq!(block.len(), AES128_BLOCK_SIZE);
    assert_eq!(key.len(), AES128_BLOCK_SIZE);

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
    // Important! Disable padding, otherwise decryption will fail since our block doesn't have valid padding.
    crypter.pad(false);

    // Output buffer must be at least 32 bytes, otherwise OpenSSL complains.
    let mut out = [0u8; 32];
    let count = crypter.update(block, &mut out)?;
    crypter.finalize(&mut out[count..])?;

    Ok(out[..AES128_BLOCK_SIZE].try_into().unwrap())
}

pub fn decrypt_aes_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(key.len(), AES128_BLOCK_SIZE);
    assert_eq!(iv.len(), AES128_BLOCK_SIZE);
    let mut cur_iv = iv.to_vec();
    let mut decoded_msg = Vec::<u8>::with_capacity(ciphertext.len());
    assert_eq!(ciphertext.len() % AES128_BLOCK_SIZE, 0);
    for i in (0..ciphertext.len()).step_by(AES128_BLOCK_SIZE) {
        let block = &ciphertext[i..i + AES128_BLOCK_SIZE];
        let decrypted = decrypt_aes_block(block, key)?;
        let mut decoded_block = xor(&decrypted, &cur_iv)?;
        if i == ciphertext.len() - AES128_BLOCK_SIZE {
            // Last block. We need to remove the padding.
            if let Some(last) = decoded_block.last() {
                decoded_block.truncate(decoded_block.len() - *last as usize);
            } else {
                panic!("This shouldn't happen!");
            }
        }
        decoded_msg.append(&mut decoded_block);
        cur_iv = block.to_vec();
    }
    Ok(decoded_msg)
}

pub fn get_random_bytes(num_bytes: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; num_bytes];
    rand::fill(&mut bytes[..]);
    bytes.to_vec()
}

pub fn encrypt_aes_block(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut encrypted = encrypt(Cipher::aes_128_ecb(), key, None, ciphertext)?;
    // OpenSSL adds padding (and encrypts it), which is not what we want.
    encrypted.truncate(AES128_BLOCK_SIZE);
    Ok(encrypted)
}

pub fn encrypt_aes_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(key.len(), AES128_BLOCK_SIZE);
    assert_eq!(iv.len(), AES128_BLOCK_SIZE);
    let mut cur_iv = iv.to_vec();
    let mut cipher_vec = ciphertext.to_vec();
    if cipher_vec.len() % AES128_BLOCK_SIZE != 0 {
        // Needs padding.
        let padding = AES128_BLOCK_SIZE - (ciphertext.len() % AES128_BLOCK_SIZE);
        cipher_vec.extend(std::iter::repeat(padding as u8).take(padding));
    } else {
        // Add dummy block.
        cipher_vec.extend(std::iter::repeat(AES128_BLOCK_SIZE as u8).take(AES128_BLOCK_SIZE));
    }
    // Note: IV is not included at the start!
    let mut encrypted_msg = Vec::<u8>::with_capacity(cipher_vec.len());
    for i in (0..cipher_vec.len()).step_by(AES128_BLOCK_SIZE) {
        let block = &cipher_vec[i..i + AES128_BLOCK_SIZE];
        let xored_block = xor(&block, &cur_iv)?;
        let encrypted = encrypt_aes_block(&xored_block, key)?;
        encrypted_msg.append(&mut encrypted.clone());
        cur_iv = encrypted;
    }
    Ok(encrypted_msg)
}

// ***** TESTS *****

#[test]
fn test_hamming_distance() {
    let bytes1 = "this is a test".as_bytes();
    let bytes2 = "wokka wokka!!!".as_bytes();
    let distance = hamming_distance(bytes1, bytes2);
    assert_eq!(distance, 37);
}

#[test]
fn test_aes128_cbc() {
    let message = "This is a test message with some text to encrypt yada yada yada.".as_bytes();
    let key = "Rick Sanchez....".as_bytes();
    let iv = [0u8; 16];
    let encrypted = encrypt_aes_cbc(message, key, &iv).unwrap();
    let decrypted = decrypt_aes_cbc(&encrypted, key, &iv).unwrap();
    assert_eq!(message, decrypted);
}

#[test]
fn test_aes128_ecb() {
    let message = "This is a test message with some text to encrypt yada yada yada.".as_bytes();
    let key = "Rick Sanchez....".as_bytes();
    let encrypted = encrypt_aes_ecb(message, key).unwrap();
    let decrypted = decrypt_aes_ecb(&encrypted, key).unwrap();
    assert_eq!(message, decrypted);
}
