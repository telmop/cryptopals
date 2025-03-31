use cryptopals::encoding;
use cryptopals::encryption;
use cryptopals::utils;
use std::path::PathBuf;

fn pkcs7_padding(bytes: &[u8], block_size: u8) -> Vec<u8> {
    assert!((block_size as usize) >= bytes.len());
    if bytes.len() == (block_size as usize) {
        return bytes.iter().copied().collect();
    }
    let padding = block_size - (bytes.len() as u8);
    let mut result = Vec::with_capacity(block_size as usize);
    result.extend_from_slice(bytes);
    for _ in 0..padding {
        result.push(padding);
    }
    result
}

fn challenge9() {
    let bytes = "YELLOW SUBMARINE".as_bytes();
    let padded = pkcs7_padding(bytes, 20);
    let s = String::from_utf8(padded).unwrap();
    println!("{:?}", s);
}

fn challenge10() {
    let encrypted = encoding::from_base64_file(&PathBuf::from("data/10.txt")).unwrap();
    println!("{:?}", &encrypted);
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0_u8; 16];
    let decrypted_bytes = encryption::decrypt_aes_cbc(&encrypted, &key, &iv).unwrap();
    let decrypted = String::from_utf8(decrypted_bytes.clone()).unwrap();
    println!("{}", decrypted);
}

// `true` is ECB, `false` is CBC.
fn detect_ecb(ciphertext: &[u8], block_size: usize) -> bool {
    let num_blocks = ciphertext.len() / block_size;
    num_blocks != utils::count_unique_blocks(ciphertext, block_size)
}

fn challenge11() {
    let msg = "This is a test sentence".repeat(50).into_bytes();
    let num_iter = 100;
    for _ in 0..num_iter {
        let (encrypted, is_ecb) = encryption::random_encrypt(&msg);
        assert_eq!(
            detect_ecb(&encrypted, encryption::AES128_BLOCK_SIZE),
            is_ecb
        );
    }
    println!(
        "Correctly predicted {} instances of random encryption.",
        num_iter
    );
}

fn main() {
    let challenges = [challenge9, challenge10, challenge11];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 1);
        challenge();
    }
}
