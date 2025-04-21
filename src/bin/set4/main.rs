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

fn main() {
    let challenges = [challenge25];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 25);
        challenge();
    }
}
