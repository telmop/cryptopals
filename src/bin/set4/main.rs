use cryptopals::encoding;
use cryptopals::encryption;
use cryptopals::encryption::AES128_BLOCK_SIZE;
use cryptopals::hash;
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
    assert!(decrypted_str.contains(";admin=true;"));
    println!("{}", decrypted_str);
}

fn encrypt_cbc128_with_keyiv(msg: &str, key: &[u8]) -> Result<Vec<u8>> {
    encryption::encrypt_aes_cbc(msg.as_bytes(), key, key)
}

fn decrypt_cbc128_with_keyiv(ciphertext: &[u8], key: &[u8]) -> Result<String> {
    let decrypted = encryption::decrypt_aes_cbc(ciphertext, key, key)?;
    Ok(String::from_utf8(decrypted)?)
}

fn build_cbc_keyiv_attack_cipher(block: &[u8]) -> Vec<u8> {
    let mut cipher = block.to_vec();
    cipher.extend(vec![0u8; AES128_BLOCK_SIZE]);
    cipher.extend_from_slice(block);
    cipher
}

fn challenge27() {
    let msg = "A secret message that no one will know!";
    assert!(msg.len() > AES128_BLOCK_SIZE * 2); // Needs to be at least 3 blocks!
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    let encrypted = encrypt_cbc128_with_keyiv(msg, &key).unwrap();
    let mut first_block = encrypted[..AES128_BLOCK_SIZE].to_vec();
    /* Construct cipher with 3 blocks: C; 0; C.
    The decryption circuit outputs:
        * m[0] = D(k, C) xor k
        * m[1] = D(k, 0) xor C
        * m[2] = D(k, C) xor 0 = D(k, C)
    This means that m[0] xor m[2] = k! */
    {
        let attack_cipher = build_cbc_keyiv_attack_cipher(&first_block);
        let result = decrypt_cbc128_with_keyiv(&attack_cipher, &key);
        assert!(result.is_err());
    }

    // Unfortunately it's unlikely that the padding is right!
    // However, we can keep changing the cipher until we get a valid 0x1 padding by chance!
    let mut bytes = vec![];
    for byte_idx in 0..AES128_BLOCK_SIZE {
        let original_value = first_block[byte_idx];
        let mut done = false;
        for value in 0u8..=255 {
            first_block[byte_idx] = value;
            let attack = build_cbc_keyiv_attack_cipher(&first_block);
            let result = decrypt_cbc128_with_keyiv(&attack, &key);
            assert!(result.is_err());
            if let Err(e) = result {
                if let Some(utf8_error) = e.downcast_ref::<std::string::FromUtf8Error>() {
                    bytes = utf8_error.as_bytes().to_vec();
                    done = true;
                    break;
                }
            }
        }
        if done {
            break;
        }
        first_block[byte_idx] = original_value;
    }
    // CBC decoding remove the padding byte. We need to add it!
    bytes.push(0x1);
    let res_first_block = &bytes[..AES128_BLOCK_SIZE];
    let res_third_block = &bytes[2 * AES128_BLOCK_SIZE..];
    let recovered_key = encryption::xor(res_first_block, res_third_block);
    assert_eq!(key, recovered_key);
    println!("Recovered key: {:?}", recovered_key);

    // The solution above is too "brute-forcy". A better alternative is to
    // craft the ciphertext as C1 0 C1 C2 C3. This way, padding is correct
    // (as long as C1 C2 C3 is a valid cipher).
    {
        let mut new_attack_cipher = encrypted[..AES128_BLOCK_SIZE].to_vec();
        new_attack_cipher.extend(vec![0u8; AES128_BLOCK_SIZE]);
        new_attack_cipher.extend_from_slice(&encrypted);
        let result = decrypt_cbc128_with_keyiv(&new_attack_cipher, &key);
        assert!(result.is_err());
        if let Err(e) = result {
            if let Some(utf8_error) = e.downcast_ref::<std::string::FromUtf8Error>() {
                let err_bytes = utf8_error.as_bytes();
                let new_recovered = encryption::xor(
                    &err_bytes[..AES128_BLOCK_SIZE],
                    &err_bytes[2 * AES128_BLOCK_SIZE..3 * AES128_BLOCK_SIZE],
                );
                assert_eq!(key, new_recovered);
            }
        }
    }
}

fn sha1_mac(msg: &[u8], key: &[u8]) -> [u8; 20] {
    let mut input = key.to_vec();
    input.extend_from_slice(msg);
    let sha1 = hash::Sha1::new();
    sha1.compute(&input)
}

fn challenge28() {
    let sha1_hash = sha1_mac(b"secure message", b"secret key");
    println!("{:?}", sha1_hash);
}

fn challenge29() {
    let orig_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let key = b"secret key";
    let new_message = b";admin=true";

    // First find out what the goal hash is. Ie, the hash that we would get if we passed
    // sha1 the key, the original message, the padding, and the new message.
    let padded_msg = {
        let mut tmp = key.to_vec();
        tmp.extend_from_slice(orig_msg);
        let mut padded = hash::Sha1::pad_msg(tmp.to_vec(), None);
        padded.extend_from_slice(new_message);
        padded
    };
    let sha1 = hash::Sha1::new();
    let goal_hash = sha1.compute(&padded_msg);

    // Now compute the actual hash with just the original message.
    let hash = sha1_mac(orig_msg, key);

    // Initialize the forger sha1.
    let h0 = u32::from_be_bytes(hash[0..4].try_into().unwrap());
    let h1 = u32::from_be_bytes(hash[4..8].try_into().unwrap());
    let h2 = u32::from_be_bytes(hash[8..12].try_into().unwrap());
    let h3 = u32::from_be_bytes(hash[12..16].try_into().unwrap());
    let h4 = u32::from_be_bytes(hash[16..20].try_into().unwrap());
    let sha1_forger = hash::Sha1::init(h0, h1, h2, h3, h4);

    // For the length, we need to account all of the message: key, original message, padding, and the new message.
    // A real attacker wouldn't know the length of the original message. They can try a wide range of lengths,
    // though, and submit all MACs to the server.
    let forged_length = (8 * padded_msg.len()) as u64;
    let forged_padded = hash::Sha1::pad_msg(new_message.to_vec(), Some(forged_length));
    let forged_hash = sha1_forger.compute(&forged_padded);
    assert_eq!(forged_hash, goal_hash);
    println!("Hashes match: {:?} == {:?}", forged_hash, goal_hash);
}

fn md4_mac(msg: &[u8], key: &[u8]) -> [u8; 16] {
    let mut input = key.to_vec();
    input.extend_from_slice(msg);
    let md4 = hash::Md4::new();
    md4.compute(&input)
}

// Pretty much the same as challenge 29 but using MD4.
fn challenge30() {
    let orig_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let key = b"secret key";
    let new_message = b";admin=true";

    // First find out what the goal hash is. Ie, the hash that we would get if we passed
    // md4 the key, the original message, the padding, and the new message.
    let padded_msg = {
        let mut tmp = key.to_vec();
        tmp.extend_from_slice(orig_msg);
        let mut padded = hash::Md4::pad_msg(tmp.to_vec(), None);
        padded.extend_from_slice(new_message);
        padded
    };
    let md4 = hash::Md4::new();
    let goal_hash = md4.compute(&padded_msg);

    // Now compute the actual hash with just the original message.
    let hash = md4_mac(orig_msg, key);

    // Initialize the forger md4. Notice the lower-endianness.
    let a = u32::from_le_bytes(hash[0..4].try_into().unwrap());
    let b = u32::from_le_bytes(hash[4..8].try_into().unwrap());
    let c = u32::from_le_bytes(hash[8..12].try_into().unwrap());
    let d = u32::from_le_bytes(hash[12..16].try_into().unwrap());
    let md4_forger = hash::Md4::init(a, b, c, d);

    let forged_length = (8 * padded_msg.len()) as u64;
    let forged_padded = hash::Md4::pad_msg(new_message.to_vec(), Some(forged_length));
    let forged_hash = md4_forger.compute(&forged_padded);
    assert_eq!(forged_hash, goal_hash);
    println!("Hashes match: {:?} == {:?}", forged_hash, goal_hash);
}

fn main() {
    let challenges = [
        challenge25,
        challenge26,
        challenge27,
        challenge28,
        challenge29,
        challenge30,
    ];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 25);
        challenge();
    }
}
