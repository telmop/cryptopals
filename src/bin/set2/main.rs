use cryptopals::encoding;
use cryptopals::encryption;
use cryptopals::encryption::AES128_BLOCK_SIZE;
use cryptopals::utils;
use rand::Rng;
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

fn random_encrypt(ciphertext: &[u8]) -> (Vec<u8>, bool) {
    let mut rng = rand::rng();
    let num_bytes_before: usize = rng.random_range(5..=10);
    let bytes_before = encryption::get_random_bytes(num_bytes_before);
    let num_bytes_after: usize = rng.random_range(5..=10);
    let bytes_after = encryption::get_random_bytes(num_bytes_after);
    let mut cipher_vec = Vec::with_capacity(ciphertext.len() + num_bytes_before + num_bytes_after);
    cipher_vec.extend(bytes_before);
    cipher_vec.extend_from_slice(ciphertext);
    cipher_vec.extend(bytes_after);

    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    if rng.random() {
        // CBC.
        let iv = encryption::get_random_bytes(AES128_BLOCK_SIZE);
        (
            encryption::encrypt_aes_cbc(&cipher_vec, &key, &iv).unwrap(),
            false,
        )
    } else {
        // ECB.
        (
            encryption::encrypt_aes_ecb(&cipher_vec, &key).unwrap(),
            true,
        )
    }
}

fn challenge11() {
    let msg = "This is a test sentence".repeat(50).into_bytes();
    let num_iter = 100;
    for _ in 0..num_iter {
        let (encrypted, is_ecb) = random_encrypt(&msg);
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
