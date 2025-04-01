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

fn encrypt_with_hidden(msg: &[u8], key: &[u8]) -> Vec<u8> {
    let hidden_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let hidden = encoding::b64decode(hidden_b64).expect("Should be valid b64");
    let mut final_msg = msg.to_vec();
    final_msg.extend(hidden);
    encryption::encrypt_aes_ecb(&final_msg, key).unwrap()
}

fn find_next_byte(known: &[u8], key: &[u8]) -> Option<u8> {
    let block_size = key.len();
    let mut last_bytes;
    if known.len() < block_size {
        last_bytes = vec![b'A'; block_size - 1 - known.len()];
        last_bytes.extend_from_slice(known);
    } else {
        last_bytes = known[known.len() - (block_size - 1)..].to_vec();
    }

    // Important: the padding is always b'A' as otherwise at some point last_bytes
    // and padding would match with each other.
    // If you draw a table of known.len() -> padding.len(), you'll find out it
    // needs to match: (y + x) % block_size = block_size - 1.
    // <=> (y + x = block_size - 1) mod block_size.
    // <=> y = (block_size - 1 - x) % block_size.
    // Since known.len() is usize, Rust will complain if we do block_size - 1 - known.len()
    // and known.len() > block_size - 1.
    // To fix this, we apply known.len() % block_size.
    let padding = vec![b'A'; (block_size - 1 - known.len() % block_size) % block_size];
    for guess_byte in 0..255 {
        let mut guess = last_bytes.clone();
        guess.push(guess_byte); // At this point, len() = block_size.

        guess.extend(padding.clone());
        let encrypted = encrypt_with_hidden(&guess, &key);
        if detect_ecb(&encrypted, block_size) {
            // Found correct byte.
            return Some(guess_byte);
        }
    }
    None
}

fn challenge12() {
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);

    // First find the block size.
    // It is the smallest increment between ciphertext lengths.
    let mut block_size = 0;
    let orig_len = encrypt_with_hidden(&[], &key).len();
    for guess in 1..64 {
        let msg = vec![b'A'; guess];
        let encrypted = encrypt_with_hidden(&msg, &key);
        if encrypted.len() > orig_len {
            block_size = encrypted.len() - orig_len;
            break;
        }
    }
    println!("Found block size: {}", block_size);

    // Find out it's encrypted with ECB.
    {
        let msg = vec![b'A'; block_size * 2];
        let encrypted = encrypt_with_hidden(&msg, &key);
        assert!(detect_ecb(&encrypted, block_size));
        println!("It's ECB!");
    }

    // Verify that the hidden message itself doesn't have repeated bytes.
    assert!(!detect_ecb(&encrypt_with_hidden(&[], &key), block_size));

    // The message is 138 bytes :)
    let msg_len: usize = 138;
    let mut known_bytes = Vec::<u8>::with_capacity(msg_len);
    while known_bytes.len() != msg_len {
        let new_byte = find_next_byte(&known_bytes, &key).unwrap();
        known_bytes.push(new_byte);
    }
    let decoded = String::from_utf8(known_bytes).unwrap();
    println!("Decoded message: {}", decoded);
}

fn main() {
    let challenges = [challenge9, challenge10, challenge11, challenge12];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 9);
        challenge();
    }
}
