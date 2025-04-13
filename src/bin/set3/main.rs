use cryptopals::attack;
use cryptopals::encoding;
use cryptopals::encryption;
use cryptopals::encryption::AES128_BLOCK_SIZE;
use cryptopals::random;
use rand::prelude::{IteratorRandom, Rng};
use std::cmp;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn attack_fixed_nonce_ctr(encrypted_msgs: &[Vec<u8>]) -> Vec<u8> {
    let max_length = encrypted_msgs
        .iter()
        .map(|msg| msg.len())
        .fold(0, |acc, x| cmp::max(acc, x));
    let mut key = Vec::with_capacity(max_length);
    for i in 0..max_length {
        let mut relevant_bytes = Vec::with_capacity(encrypted_msgs.len());
        for encrypted in encrypted_msgs {
            if encrypted.len() <= i {
                continue;
            }
            relevant_bytes.push(encrypted[i]);
        }
        let (best_key, _) = attack::find_best_key(&relevant_bytes, attack::Score::Quadratic);
        key.push(best_key);
    }
    key
}

// For both challenges 19 and 20, the last few bytes are off. This is because there are not
// enough unigrams to be accurate. We could use common bigrams, but I'm lazy :)
fn challenge19() {
    let msgs: Vec<Vec<u8>> = vec![
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    ]
    .into_iter()
    .map(|s| encoding::b64decode(s).unwrap())
    .collect();
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    let nonce = vec![0u8; AES128_BLOCK_SIZE / 2];

    let encrypted_msgs: Vec<Vec<u8>> = msgs
        .iter()
        .map(|msg| encryption::aes128_ctr(&msg, &key, &nonce))
        .collect();
    let guess = attack_fixed_nonce_ctr(&encrypted_msgs);
    for encrypted in &encrypted_msgs {
        let decrypted = encryption::truncated_xor(encrypted, &guess);
        println!("{}", String::from_utf8(decrypted).unwrap());
    }
}

fn challenge20() {
    let f = File::open(PathBuf::from("data/20.txt")).expect("Couldn't open file");
    let reader = BufReader::new(f);
    let msgs: Vec<Vec<u8>> = reader
        .lines()
        .map(|s| encoding::b64decode(s.unwrap().trim()).unwrap())
        .collect();
    let key = encryption::get_random_bytes(AES128_BLOCK_SIZE);
    let nonce = vec![0u8; AES128_BLOCK_SIZE / 2];

    let encrypted_msgs: Vec<Vec<u8>> = msgs
        .iter()
        .map(|msg| encryption::aes128_ctr(&msg, &key, &nonce))
        .collect();
    let guess = attack_fixed_nonce_ctr(&encrypted_msgs);
    for encrypted in &encrypted_msgs {
        let decrypted = encryption::truncated_xor(encrypted, &guess);
        println!("{}", String::from_utf8(decrypted).unwrap());
    }
}

fn challenge21() {
    let mut rng = random::MT19937::new(0);
    assert_eq!(rng.random(), 2357136044);
}

fn sleep(time: u32) {
    let wait_time = std::time::Duration::from_secs(time as u64);
    std::thread::sleep(wait_time);
}

fn get_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

fn gen_random_with_wait(min_wait: u32, max_wait: u32, fake_wait: bool) -> (u32, u32) {
    let mut rng = rand::rng();
    let wait1 = rng.random_range(min_wait..=max_wait);
    let dt;
    if !fake_wait {
        sleep(wait1);
        dt = 0;
    } else {
        dt = wait1;
    }
    let seed = get_timestamp_seconds() as u32 - dt;
    let mut mt = random::MT19937::new(seed);
    if !fake_wait {
        sleep(rng.random_range(min_wait..=max_wait));
    }
    (mt.random(), seed)
}

fn challenge22() {
    let min_wait = 40;
    let max_wait = 1000;
    let (random_n, seed) = gen_random_with_wait(min_wait, max_wait, true);

    let timestamp = get_timestamp_seconds() as u32;
    for dt in 0..=3 * max_wait {
        let mut mt = random::MT19937::new(timestamp - dt);
        let n = mt.random();
        if n == random_n {
            // Found correct seed.
            assert_eq!(timestamp - dt, seed);
            println!("Found seed: {}", timestamp - dt);
            break;
        }
    }
}

fn challenge23() {
    let mut rng = random::MT19937::new(19650218);
    let mut clone = random::MT19937::empty();
    for _ in 0..random::N {
        let value = rng.random();
        clone.reconstruct_state(value);
    }
    for _ in 0..100 {
        assert_eq!(rng.random(), clone.random());
    }
    println!("Values match: {} {}", rng.random(), clone.random());
}

fn generate_random_bytes_from_mt19937(seed: u16, length: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(length);
    // +3 (= +4 -1) to get the ceiling.
    let num_to_gen = (length + 3) / 4;
    let mut rng = random::MT19937::new(seed as u32);
    for _ in 0..num_to_gen {
        let value = rng.random();
        key.push((value & 0xFF) as u8);
        key.push(((value >> 8) & 0xFF) as u8);
        key.push(((value >> 16) & 0xFF) as u8);
        key.push(((value >> 24) & 0xFF) as u8);
    }
    key
}

fn mt19937_one_time_pad(msg: &[u8], seed: u16) -> Vec<u8> {
    let key = generate_random_bytes_from_mt19937(seed, msg.len());
    encryption::truncated_xor(msg, &key)
}

fn is_mt19937_generated_token(token: &[u8]) -> bool {
    for guess in 0..u16::MAX {
        let guess_token = generate_random_bytes_from_mt19937(guess, 16);
        if &guess_token == token {
            return true;
        }
    }
    false
}

fn challenge24() {
    // Part 1: validate encryption works.
    {
        let msg = "This is a relatively short secret message...".as_bytes();
        let mut rng = rand::rng();
        let seed: u16 = rng.random();
        let encrypted = mt19937_one_time_pad(msg, seed);
        // Decrypt function is the same, since this is a xor.
        let decrypted = mt19937_one_time_pad(&encrypted, seed);
        assert_eq!(msg, decrypted);
    }

    // Part 2: break u16 key.
    {
        let mut rng = rand::rng();
        let seed: u16 = rng.random();
        let prefix_size: usize = rng.random_range(5..=20);
        let mut msg = encryption::get_random_bytes(prefix_size);
        msg.extend(vec![b'A'; 14]);
        let encrypted = mt19937_one_time_pad(&msg, seed);
        for guess in 0..u16::MAX {
            let decrypted = mt19937_one_time_pad(&encrypted, guess);
            if &decrypted[decrypted.len() - 14..decrypted.len()] == &vec![b'A'; 14] {
                assert_eq!(seed, guess);
                println!("Found seed: {}", guess);
                break;
            }
        }
    }

    // Part 3: password reset token.
    {
        let unix_time = (get_timestamp_seconds() & (u16::MAX as u64)) as u16;
        let token = generate_random_bytes_from_mt19937(unix_time, 16);
        assert!(is_mt19937_generated_token(&token));
        let proper_token = encryption::get_random_bytes(16);
        assert!(!is_mt19937_generated_token(&proper_token));
    }
}

fn main() {
    let challenges = [
        challenge17,
        challenge18,
        challenge19,
        challenge20,
        challenge21,
        challenge22,
        challenge23,
        challenge24,
    ];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 17);
        challenge();
    }
}
