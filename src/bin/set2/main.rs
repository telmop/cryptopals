use cryptopals::encoding;
use cryptopals::encryption;
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
    let decrypted = String::from_utf8(decrypted_bytes).unwrap();
    println!("{}", decrypted);
}

fn main() {
    let challenges = [challenge9, challenge10];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 1);
        challenge();
    }
}
