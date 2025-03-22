use std::collections::HashMap;
use std::collections::HashSet;

fn challenge1() {
    let x = cryptopals::hexstr_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    let encoded = cryptopals::b64encode(&x).unwrap();
    assert_eq!(
        encoded,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}

fn challenge2() {
    let bytes1 = cryptopals::hexstr_to_bytes("1c0111001f010100061a024b53535009181c").unwrap();
    let bytes2 = cryptopals::hexstr_to_bytes("686974207468652062756c6c277320657965").unwrap();
    let result = cryptopals::xor(&bytes1, &bytes2).unwrap();
    let result_str = cryptopals::bytes_to_hexstr(&result);
    assert_eq!(result_str, "746865206b696420646f6e277420706c6179");
}

fn get_most_frequent_chars(s: &str) -> Vec<(char, usize)> {
    let mut counts = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }

    let mut items: Vec<(char, usize)> = counts.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1)); // Reverse order.
    items
}

fn count_matches(chars: &[char]) -> u32 {
    // English frequencies: 'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070, 'n': 0.067.
    // Note: Including space is SUPER important. Otherwise it won't work :)
    let most_freq = HashSet::from(['e', 't', 'a', 'o', 'i', 'n', ' ']);
    let mut matches = 0;
    for i in 0..most_freq.len() {
        if i > chars.len() {
            break;
        }
        if most_freq.contains(&chars[i]) {
            matches += 1;
        }
    }
    matches
}

fn challenge3() {
    let bytes = cryptopals::hexstr_to_bytes(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    )
    .unwrap();
    let mut best_matches = 0;
    let mut best_key = 0;
    for mask in 0_u8..=255_u8 {
        let decrypted = cryptopals::sliding_xor(&bytes, &vec![mask]);
        match String::from_utf8(decrypted) {
            Err(_) => {
                continue;
            }
            Ok(mut decrypted_str) => {
                decrypted_str.make_ascii_lowercase();
                let counts = get_most_frequent_chars(&decrypted_str);
                let cur_matches =
                    count_matches(&counts.into_iter().map(|(a, _)| a).collect::<Vec<char>>());
                if cur_matches > best_matches {
                    best_matches = cur_matches;
                    best_key = mask;
                }
            }
        }
    }
    let decrypted = String::from_utf8(cryptopals::sliding_xor(&bytes, &vec![best_key])).unwrap();
    println!(
        "Best key: {} ({}); #matches: {}; decrypted: {}",
        best_key as char, best_key, best_matches, decrypted
    );
}

fn main() {
    println!("Running challenge 1");
    challenge1();

    println!("Running challenge 2");
    challenge2();

    println!("Running challenge 3");
    challenge3();
}
