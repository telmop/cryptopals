use openssl::symm::{decrypt, Cipher, Crypter, Mode};

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

pub fn decrypt_aes_ecb(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    Ok(decrypt(Cipher::aes_128_ecb(), key, None, ciphertext)?)
}

pub fn decrypt_aes_block(block: &[u8], key: &[u8]) -> Result<[u8; 16]> {
    assert_eq!(block.len(), 16);
    assert_eq!(key.len(), 16);

    let mut crypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
    // Important! Disable padding, otherwise decryption will fail since our block doesn't have valid padding.
    crypter.pad(false);

    // Output buffer must be at least 32 bytes, otherwise OpenSSL complains.
    let mut out = [0u8; 32];
    let count = crypter.update(block, &mut out)?;
    crypter.finalize(&mut out[count..])?;

    Ok(out[..16].try_into().unwrap())
}

pub fn decrypt_aes_cbc(cyphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(key.len(), iv.len());
    let block_size = iv.len();
    let mut cur_iv = iv.to_vec();
    let mut decoded_msg = Vec::<u8>::with_capacity(cyphertext.len());
    assert_eq!(cyphertext.len() % block_size, 0);
    for i in (0..cyphertext.len()).step_by(block_size) {
        let block = &cyphertext[i..i + block_size];
        let decrypted = decrypt_aes_block(block, key)?;
        let mut decoded_block = xor(&decrypted, &cur_iv)?;
        decoded_msg.append(&mut decoded_block);
        cur_iv = block.to_vec();
    }
    Ok(decoded_msg)
}

// ***** TESTS *****

#[test]
fn test_hamming_distance() {
    let bytes1 = "this is a test".as_bytes();
    let bytes2 = "wokka wokka!!!".as_bytes();
    let distance = hamming_distance(bytes1, bytes2);
    assert_eq!(distance, 37);
}
