use cryptopals::encoding;
use cryptopals::encryption;
use cryptopals::encryption::AES128_BLOCK_SIZE;
use rand::prelude::IteratorRandom;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

fn encrypt_random_message(key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    let b64_strs = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];
    let msgs = b64_strs
        .into_iter()
        .map(|b64_str| encoding::b64decode(b64_str).unwrap());
    let mut rng = rand::rng();
    let msg = msgs.choose(&mut rng).unwrap();
    println!("Original: {}", std::str::from_utf8(&msg).unwrap());
    encryption::encrypt_aes_cbc(&msg, key, iv)
}

// I don't like the fact that this function effectively returns its output
// through the mutable references `guesses`.
fn recursive_guess_byte(
    ciphertext: &[u8],
    key: &[u8],
    iv: &[u8], // We don't need to pass iv: it only affects the decryption of the previous block.
    block_size: usize,
    guess_idx: usize,
    guesses: &mut [u8],
) -> bool {
    let mut mask = vec![0u8; 2 * block_size];
    mask[block_size - guess_idx..block_size].fill(guess_idx as u8);
    let mut xored_mask = encryption::xor(&mask, guesses);
    for guess in 0u8..=255 {
        xored_mask[block_size - guess_idx] ^= guess;
        let xored = encryption::xor(ciphertext, &xored_mask);
        if encryption::decrypt_aes_cbc(&xored, key, iv).is_ok() {
            guesses[block_size - guess_idx] = guess;
            if guess_idx == block_size {
                // Fully decrypted.
                return true;
            }
            if recursive_guess_byte(ciphertext, key, iv, block_size, guess_idx + 1, guesses) {
                return true;
            }
        }
        if guess == 255 {
            // No match found.
            return false;
        }
        // Not the right guess: undo xoring.
        xored_mask[block_size - guess_idx] ^= guess;
    }
    false
}

fn cbc_padding_attack(ciphertext: &[u8], block_size: usize, key: &[u8], iv: &[u8]) -> Vec<u8> {
    assert_eq!(ciphertext.len() % block_size, 0);
    assert!(ciphertext.len() >= 2 * block_size);
    let mut cipher_vec = iv.to_vec();
    cipher_vec.extend_from_slice(ciphertext);
    let mut decrypted = Vec::with_capacity(ciphertext.len());
    let mut cur_iv = iv;

    for block_idx in (0..cipher_vec.len() - block_size).step_by(block_size) {
        if block_idx > 0 {
            // Changing the IV doesn't matter, as it only affects the previous block, but we do it for correctness.
            cur_iv = &cipher_vec[block_idx - block_size..block_idx];
        }
        let relevant_cipher = &cipher_vec[block_idx..block_idx + 2 * block_size];
        let mut guesses = vec![0u8; block_size];
        assert!(recursive_guess_byte(
            &relevant_cipher,
            key,
            cur_iv,
            block_size,
            1,
            &mut guesses
        ));
        if block_idx == cipher_vec.len() - 2 * block_size {
            // Last block. Remove padding. `unwrap` is safe since the assert passed.
            guesses = encryption::undo_pkcs7_padding(&guesses).unwrap();
        }
        decrypted.extend(guesses);
    }
    decrypted
}

fn challenge17() {
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    let iv = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    let encrypted = encrypt_random_message(&key, &iv).unwrap();
    let decrypted = cbc_padding_attack(&encrypted, AES128_BLOCK_SIZE, &key, &iv);
    println!("Decrypted: {}", std::str::from_utf8(&decrypted).unwrap());
}

fn challenge18() {
    let encrypted = encoding::b64decode(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
    )
    .unwrap();
    let key = "YELLOW SUBMARINE".as_bytes();
    let nonce = vec![0u8; AES128_BLOCK_SIZE / 2];
    let decrypted = encryption::aes128_ctr(&encrypted, key, &nonce);
    println!("Decrypted: {}", std::str::from_utf8(&decrypted).unwrap());
    assert_eq!(encryption::aes128_ctr(&decrypted, key, &nonce), encrypted);
}

fn main() {
    let challenges = [challenge17, challenge18];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 17);
        challenge();
    }
}
