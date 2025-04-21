use cryptopals::encoding;
use cryptopals::encryption;
use cryptopals::encryption::AES128_BLOCK_SIZE;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

fn load_ecb_encrypted_file(filename: &Path, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let encrypted = encoding::from_base64_file(filename).unwrap();
    encryption::decrypt_aes_cbc(&encrypted, &key, &iv).unwrap()
}

fn edit_ctr(
    ciphertext: &[u8],
    key: &[u8],
    nonce: &[u8],
    offset: usize,
    newtext: &[u8],
) -> Result<Vec<u8>> {
    if offset >= ciphertext.len() {
        return Err("`offset` must be less than the ciphertext length".into());
    }
    // Place newtext in the right position and encrypt.
    let mut padded_newtext = vec![0u8; offset];
    padded_newtext.extend_from_slice(newtext);
    let encrypted_newtext = encryption::aes128_ctr(&padded_newtext, key, nonce);

    let suffix = if offset + newtext.len() < ciphertext.len() {
        ciphertext[offset + newtext.len()..].to_vec()
    } else {
        vec![]
    };
    let mut cipher_vec = ciphertext.to_vec();
    cipher_vec.truncate(offset);
    cipher_vec.extend_from_slice(&encrypted_newtext[offset..]);
    cipher_vec.extend(suffix);
    Ok(cipher_vec)
}

fn challenge25() {
    let msg = load_ecb_encrypted_file(
        &PathBuf::from("data/10.txt"),
        "YELLOW SUBMARINE".as_bytes(),
        &[0u8; AES128_BLOCK_SIZE],
    );
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    let nonce = [0u8; AES128_BLOCK_SIZE / 2];
    let encrypted = encryption::aes128_ctr(&msg, &key, &nonce);
    // The attack is simple: if nextext is all zeros, then the encrypted version is just the key :)
    let recovered_key = edit_ctr(&encrypted, &key, &nonce, 0, &vec![0u8; encrypted.len()]).unwrap();
    let decrypted = encryption::xor(&encrypted, &recovered_key);
    println!("{}", std::str::from_utf8(&decrypted).unwrap());
    assert_eq!(msg, decrypted);
}

// This and below (challenge26) were mostly copied from set2, challange 16.
fn ctr_user_data_encode(user_data: &str, key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();
    let mut user_data_str = user_data.to_string();
    // Escape special characters to not make the attacker's life as easy.
    user_data_str = user_data_str.replace(";", "").replace("=", "");
    let mut data = prefix.to_vec();
    data.extend(user_data_str.into_bytes());
    data.extend_from_slice(suffix);
    encryption::aes128_ctr(&data, key, nonce)
}

fn challenge26() {
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    let nonce = [0u8; AES128_BLOCK_SIZE / 2];
    // Our goal is to decode ";admin=true;". We can't use ';' and '='.
    // ';' in ascii is 59. ':' (allowed character) is 58 - 1 bit difference.
    // Likewise, '=' is 61, and '<' is 60 - 1 bit difference.
    // If we change the correct 3 bits, we get the right decoded string.
    let mut encrypted = ctr_user_data_encode(":admin<true", &key, &nonce);

    // We want to change the 32nd and 38th characters (`:` -> `;`, and `<` -> `=`).
    encrypted[32] ^= 0b1;
    encrypted[38] ^= 0b1;
    let decrypted = encryption::aes128_ctr(&encrypted, &key, &nonce);
    let decrypted_str = String::from_utf8_lossy(&decrypted);
    `assert!(decrypted_str.contains(";admin=true;"));
    println!("{}", decrypted_str);
}

fn main() {
    let challenges = [challenge25, challenge26];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 25);
        challenge();
    }
}
