use std::fs::File;
use std::io::{BufRead, BufReader};
use std::iter::Sum;
use std::path::PathBuf;

fn challenge1() {
    let x = cryptopals::encoding::hexstr_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    let encoded = cryptopals::encoding::b64encode(&x).unwrap();
    assert_eq!(
        encoded,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}

fn challenge2() {
    let bytes1 =
        cryptopals::encoding::hexstr_to_bytes("1c0111001f010100061a024b53535009181c").unwrap();
    let bytes2 =
        cryptopals::encoding::hexstr_to_bytes("686974207468652062756c6c277320657965").unwrap();
    let result = cryptopals::encryption::xor(&bytes1, &bytes2);
    let result_str = cryptopals::encoding::bytes_to_hexstr(&result);
    assert_eq!(result_str, "746865206b696420646f6e277420706c6179");
}

fn challenge3() {
    let hexstr = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let bytes = cryptopals::encoding::hexstr_to_bytes(hexstr).unwrap();
    let (best_key, best_score) = cryptopals::attack::find_best_key(&bytes);
    let decrypted =
        String::from_utf8(cryptopals::encryption::sliding_xor(&bytes, &vec![best_key])).unwrap();
    println!(
        "Best key: {} ({}); score: {}; decrypted: {}",
        best_key as char, best_key, best_score, decrypted
    );
}

fn challenge4() {
    let f = File::open(PathBuf::from("data/4.txt")).expect("Couldn't open file");
    let reader = BufReader::new(f);
    let mut highest_score = 0;
    let mut guess_line = "".to_string();
    let mut key = 0;
    for line_result in reader.lines() {
        let line = line_result.expect("Error reading line.");
        let bytes = cryptopals::encoding::hexstr_to_bytes(&line).unwrap();
        let (best_key, best_score) = cryptopals::attack::find_best_key(&bytes);
        if best_score > highest_score {
            highest_score = best_score;
            key = best_key;
            guess_line = line;
        }
    }
    let bytes = cryptopals::encoding::hexstr_to_bytes(&guess_line).unwrap();
    let decrypted =
        String::from_utf8(cryptopals::encryption::sliding_xor(&bytes, &vec![key])).unwrap();
    println!(
        "{} -> `{}`; Key: {} ({}); Matches: {}",
        guess_line, decrypted, key as char, key, highest_score
    );
}

fn challenge5() {
    let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    let key_bytes = key.as_bytes();
    let msg_bytes = message.as_bytes();
    let encrypted_bytes = cryptopals::encryption::sliding_xor(msg_bytes, key_bytes);
    let encrypted = cryptopals::encoding::bytes_to_hexstr(&encrypted_bytes);
    assert_eq!(encrypted, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
}

fn find_best_multibyte_key(encrypted: &[u8], key_size: usize) -> (Vec<u8>, Vec<u32>) {
    let mut decryption_key = Vec::with_capacity(key_size);
    let mut scores = Vec::with_capacity(key_size);
    for i in 0..key_size {
        let relevant_bytes: Vec<u8> = encrypted
            .iter()
            .skip(i)
            .step_by(key_size)
            .cloned()
            .collect();
        let (key, score) = cryptopals::attack::find_best_key(&relevant_bytes);
        decryption_key.push(key);
        scores.push(score);
    }
    (decryption_key, scores)
}

fn average<T>(numbers: &[T]) -> f64
where
    T: Copy + Sum,
    f64: From<T>,
{
    if numbers.is_empty() {
        return 0.0;
    }

    let sum = numbers.iter().copied().sum();

    let sum_f64 = f64::from(sum);
    sum_f64 / (numbers.len() as f64)
}

fn challenge6() {
    let bytes = cryptopals::encoding::from_base64_file(&PathBuf::from("data/6.txt")).unwrap();

    /*
    Explanation for this part:
        * Original message: ABCDEFGH
        * Key: XYZ
        * Encrypted message: (A.X)(B.Y)(C.Z)(D.X)(E.Y)(F.Z)(G.X)(H.Y) (X1.X2) = xor(X1, X2).
    The Hamming distance is just XOR + count_ones().
    If we guess key_size=3, we will compute: (A.X.D.X)(B.Y.E.Y)(C.Z.F.Z) = (A.D)(B.E)(C.F)
    In ASCII, all characters are close together. If two characters are the same, XOR = 0.
    But even if not, they'll likely be closer than random digits.
    If we guess key_size=2, we will compute: (A.X.C.Z)(B.Y.D.X)
    Similarly, for key_size=4: (A.X.E.Y)(B.Y.F.Z)(C.Z.G.X)(D.X.H.Y)
    In both these cases the output of the xor will be closer to random than when the key_size is correct.
    This means that the Hamming distance will be higher for the wrong key_size!
    */
    let mut scored_keys = Vec::<(usize, f32)>::new();
    for key_size in 2..=40 {
        let mut dist = 0;
        // Compute the distances between the first 4 blocks of bytes: 1st and 2nd, 1st and 3rd, ...
        for i in 0..4 {
            for j in (i + 1)..4 {
                let first = &bytes[i * key_size..(i + 1) * key_size];
                let second = &bytes[j * key_size..(j + 1) * key_size];
                dist += cryptopals::encryption::hamming_distance(first, second);
            }
        }
        let normalized_avg_dist = (dist as f32) / (key_size as f32);
        scored_keys.push((key_size, normalized_avg_dist));
    }
    scored_keys.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    // Only consider the 3 with the smallest score.
    let keys_to_consider = &scored_keys[..3];
    let mut best_score = 0.0;
    let mut decrypted_msg = String::new();
    let mut decryption_key = String::new();
    for (key_size, _) in keys_to_consider {
        let (key, scores) = find_best_multibyte_key(&bytes, *key_size);
        let avg_score = average(&scores);
        let decrypted = String::from_utf8(cryptopals::encryption::sliding_xor(&bytes, &key));
        if avg_score > best_score {
            best_score = avg_score;
            decrypted_msg = decrypted.unwrap_or("Oopsie, check what happened".to_string());
            decryption_key = String::from_utf8(key).unwrap_or("Something went wrong".to_string());
        }
    }
    println!(
        "Best score: {}; Key: {}; Message:\n{}",
        best_score, decryption_key, decrypted_msg
    );
}

fn challenge7() {
    let key = "YELLOW SUBMARINE".as_bytes();
    let ciphertext = cryptopals::encoding::from_base64_file(&PathBuf::from("data/7.txt")).unwrap();
    let decrypted_bytes = cryptopals::encryption::decrypt_aes_ecb(&ciphertext, key).unwrap();
    let decrypted = String::from_utf8(decrypted_bytes).unwrap();
    println!("Decrypted text: {}", decrypted);
}

fn challenge8() {
    let f = File::open(PathBuf::from("data/8.txt")).expect("Couldn't open file");
    let reader = BufReader::new(f);
    let mut min_blocks = std::usize::MAX;
    let mut ecb_line = String::new();
    let mut expected_blocks: usize = 0;
    for line_result in reader.lines() {
        let line = line_result.expect("Error reading line.");
        let bytes = cryptopals::encoding::hexstr_to_bytes(&line).unwrap();
        expected_blocks = bytes.len() / 16;
        let unique = cryptopals::utils::count_unique_blocks(&bytes, 16);
        if unique < min_blocks {
            min_blocks = unique;
            ecb_line = line;
        }
    }
    println!(
        "Expected: {}; Found: {}. Line: {}",
        expected_blocks, min_blocks, ecb_line
    );
}

fn main() {
    let challenges = [
        challenge1, challenge2, challenge3, challenge4, challenge5, challenge6, challenge7,
        challenge8,
    ];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 1);
        challenge();
    }
}
