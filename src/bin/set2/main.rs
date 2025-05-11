use cryptopals::encoding;
use cryptopals::encryption;
use cryptopals::encryption::AES128_BLOCK_SIZE;
use cryptopals::utils;
use rand::Rng;
use std::collections::HashMap;
use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

fn challenge9() {
    let bytes = "YELLOW SUBMARINE".as_bytes();
    let padded = encryption::pkcs7_padding(bytes, 20);
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
    let mut rng = rand::thread_rng();
    let num_bytes_before: usize = rng.gen_range(5..=10);
    let bytes_before = encryption::get_random_bytes(num_bytes_before);
    let num_bytes_after: usize = rng.gen_range(5..=10);
    let bytes_after = encryption::get_random_bytes(num_bytes_after);
    let mut cipher_vec = Vec::with_capacity(ciphertext.len() + num_bytes_before + num_bytes_after);
    cipher_vec.extend(bytes_before);
    cipher_vec.extend_from_slice(ciphertext);
    cipher_vec.extend(bytes_after);

    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    if rand::random() {
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

fn encrypt_with_hidden(msg: &[u8], key: &[u8], random_prefix: Option<&[u8]>) -> Vec<u8> {
    let hidden_b64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let hidden = encoding::b64decode(hidden_b64).expect("Should be valid b64");
    let mut final_msg;
    match random_prefix {
        Some(rp) => {
            final_msg = rp.to_vec();
            final_msg.extend_from_slice(msg);
        }
        None => {
            final_msg = msg.to_vec();
        }
    }
    final_msg.extend(hidden);
    encryption::encrypt_aes_ecb(&final_msg, key).unwrap()
}

fn find_next_byte(
    known: &[u8],
    key: &[u8],
    min_padding: usize,
    prefix: Option<&[u8]>, // Needed for challenge 14. Not used by this function (obviously), just passed.
) -> Option<u8> {
    let block_size = key.len();
    let mut last_bytes = vec![b'B'; min_padding]; // In case there's any prefix (Challenge 14).
    if known.len() < block_size {
        last_bytes.extend(vec![b'A'; block_size - 1 - known.len()]);
        last_bytes.extend_from_slice(known);
    } else {
        last_bytes.extend_from_slice(&known[known.len() - (block_size - 1)..]);
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
        let encrypted = encrypt_with_hidden(&guess, &key, prefix);
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
    let orig_len = encrypt_with_hidden(&[], &key, None).len();
    for guess in 1..64 {
        let msg = vec![b'A'; guess];
        let encrypted = encrypt_with_hidden(&msg, &key, None);
        if encrypted.len() > orig_len {
            block_size = encrypted.len() - orig_len;
            break;
        }
    }
    println!("Found block size: {}", block_size);

    // Find out it's encrypted with ECB.
    {
        let msg = vec![b'A'; block_size * 2];
        let encrypted = encrypt_with_hidden(&msg, &key, None);
        assert!(detect_ecb(&encrypted, block_size));
        println!("It's ECB!");
    }

    // Verify that the hidden message itself doesn't have repeated bytes.
    assert!(!detect_ecb(
        &encrypt_with_hidden(&[], &key, None),
        block_size
    ));

    // The message is 138 bytes :)
    let msg_len: usize = 138;
    let mut known_bytes = Vec::<u8>::with_capacity(msg_len);
    while known_bytes.len() != msg_len {
        let new_byte = find_next_byte(&known_bytes, &key, 0, None).unwrap();
        known_bytes.push(new_byte);
    }
    let decoded = String::from_utf8(known_bytes).unwrap();
    println!("Decoded message: {}", decoded);
}

fn parse_params(param_str: &str) -> Option<HashMap<String, String>> {
    let mut parsed = HashMap::new();
    for pair in param_str.split("&") {
        match pair.split_once("=") {
            Some((key, value)) => {
                parsed.insert(key.to_string(), value.to_string());
            }
            _ => return None,
        }
    }
    Some(parsed)
}

fn encode_profile(params: &HashMap<String, String>) -> String {
    let email = params.get("email").unwrap();
    let uid = params.get("uid").unwrap();
    let role = params.get("role").unwrap();
    format!("email={}&uid={}&role={}", email, uid, role)
}

fn profile_for(email: &str) -> Option<String> {
    if email.contains("&") || email.contains("=") {
        return None;
    }
    let profile = HashMap::from([
        ("email".to_string(), email.to_string()),
        ("uid".to_string(), "1".to_string()),
        ("role".to_string(), "user".to_string()),
    ]);
    Some(encode_profile(&profile))
}

fn challenge13() {
    let test_profile = profile_for("me@example.com").unwrap();
    assert_eq!(test_profile, "email=me@example.com&uid=1&role=user");
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);

    /* This will produce a profile like:
    email=AAAAAAAAAA admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b &uid=1&role=user
    With these 3 blocks. The 2nd block is a block we can save for later.
    \x0b is PKCS#7 padding.
    */
    let email1 = "AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    let profile1 = profile_for(email1).unwrap();
    let encrypted1 = encryption::encrypt_aes_ecb(&profile1.as_bytes(), &key).unwrap();
    let admin_block = encrypted1[AES128_BLOCK_SIZE..2 * AES128_BLOCK_SIZE].to_vec(); // Get 2nd block.

    /* This will produce a profile like:
    email=test@tests .com&uid=1&role= user
    Where the role is in its own block - which we can replace!
    */
    let email2 = "test@tests.com";
    let profile2 = profile_for(email2).unwrap();
    let encrypted2 = encryption::encrypt_aes_ecb(&profile2.as_bytes(), &key).unwrap();

    let mut attacked = encrypted2[..encrypted2.len() - AES128_BLOCK_SIZE].to_vec();
    attacked.extend(admin_block);
    let decrypted = encryption::decrypt_aes_ecb(&attacked, &key).unwrap();
    let decrypted_str = String::from_utf8(decrypted).unwrap();
    println!("{}", decrypted_str);
    let attacked_profile = parse_params(&decrypted_str).unwrap();
    assert_eq!(attacked_profile.get("role"), Some(&"admin".to_string()));
}

fn challenge14() {
    let mut rng = rand::thread_rng();
    let prefix_size = rng.gen_range(5..=20);
    let prefix = encryption::get_random_bytes(prefix_size);
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);

    // Find prefix size.
    // If we add 2 * block_size + (block_size - prefix.len()) b'A' we'll get 2 blocks of b'A'
    // and get an ECB detection. We can then find the prefix length (modulo block size).
    // prefix.len() % block_size = 3 * block_size - guess.
    // We can't distinguish a prefix length of 2 from one of block_size + 2, but it doesn't
    // matter for our purposes. All we care about is byte alignment.
    let mut estimated_length = None;
    for guess in 0..=(3 * AES128_BLOCK_SIZE) {
        let msg = vec![b'A'; guess];
        let encrypted = encrypt_with_hidden(&msg, &key, Some(&prefix));
        if detect_ecb(&encrypted, AES128_BLOCK_SIZE) {
            estimated_length = Some((3 * AES128_BLOCK_SIZE - guess) % AES128_BLOCK_SIZE);
            break;
        }
    }
    assert_eq!(estimated_length, Some(prefix.len() % AES128_BLOCK_SIZE));
    println!("Prefix length: {:?}", estimated_length);

    // Pretty much the same as for challenge 12, except that now we add extra padding so that
    // the random prefix plus our padding fills one block. After that, the challenge is exactly
    // the same as challenge 12.
    let min_padding = AES128_BLOCK_SIZE - estimated_length.unwrap();
    let msg_len: usize = 138;
    let mut known_bytes = Vec::<u8>::with_capacity(msg_len);
    while known_bytes.len() != msg_len {
        let new_byte = find_next_byte(&known_bytes, &key, min_padding, Some(&prefix)).unwrap();
        known_bytes.push(new_byte);
    }
    let decoded = String::from_utf8(known_bytes).unwrap();
    println!("Decoded message: {}", decoded);
}

fn challenge15() {
    let example1 = encryption::undo_pkcs7_padding("ICE ICE BABY\x04\x04\x04\x04".as_bytes());
    let example2 = encryption::undo_pkcs7_padding("ICE ICE BABY\x05\x05\x05\x05".as_bytes());
    let example3 = encryption::undo_pkcs7_padding("ICE ICE BABY\x01\x02\x03\x04".as_bytes());
    assert_eq!(example1, Some("ICE ICE BABY".as_bytes().to_vec()));
    assert_eq!(example2, None);
    assert_eq!(example3, None);
    println!("Completed!");
}

fn cbc_user_data_encode(user_data: &str, key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let prefix = "comment1=cooking%20MCs;userdata=".as_bytes();
    let suffix = ";comment2=%20like%20a%20pound%20of%20bacon".as_bytes();
    let mut user_data_str = user_data.to_string();
    // Escape special characters to not make the attacker's life as easy.
    user_data_str = user_data_str.replace(";", "").replace("=", "");
    let mut data = prefix.to_vec();
    data.extend(user_data_str.into_bytes());
    data.extend_from_slice(suffix);
    encryption::encrypt_aes_cbc(&data, key, iv)
}

fn challenge16() {
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    let iv = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    // Our goal is to decode ";admin=true;". We can't use ';' and '='.
    // ';' in ascii is 59. ':' (allowed character) is 58 - 1 bit difference.
    // Likewise, '=' is 61, and '<' is 60 - 1 bit difference.
    // If we change the correct 3 bits, we get the right decoded string.
    // NOTE: We don't need extra padding at the beginning because the prefix is 32 bytes,
    // a multiple of AES128_BLOCK_SIZE. If it weren't, we could just pad with a few extra
    // characters.
    let mut encrypted = cbc_user_data_encode(":admin<true", &key, &iv).unwrap();

    // We want to change the 3rd block: characters 1, and 7.
    // For all characters, we want to change the last bit, i.e., xor with 0b1.
    // Since we need to change the block before the block these characters are in,
    // the indices we have to update are: 16 + 0 = 16, and 16 + 6 = 22.
    encrypted[16] ^= 0b1;
    encrypted[22] ^= 0b1;
    let decrypted = encryption::decrypt_aes_cbc(&encrypted, &key, &iv).unwrap();
    let decrypted_str = String::from_utf8_lossy(&decrypted);
    assert!(decrypted_str.contains(";admin=true;"));
    println!("{}", decrypted_str);
}

fn main() {
    let challenges = [
        challenge9,
        challenge10,
        challenge11,
        challenge12,
        challenge13,
        challenge14,
        challenge15,
        challenge16,
    ];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 9);
        challenge();
    }
}
