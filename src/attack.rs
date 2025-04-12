use std::collections::HashMap;
use std::collections::HashSet;

fn get_most_frequent_chars(s: &str) -> Vec<(u8, usize)> {
    let mut counts = HashMap::new();
    for c in s.as_bytes() {
        *counts.entry(*c).or_insert(0) += 1;
    }

    let mut items: Vec<(u8, usize)> = counts.into_iter().collect();
    items.sort_by(|a, b| b.1.cmp(&a.1)); // Reverse order.
    items
}

fn is_control(u: u8) -> bool {
    u < 0x20 || u == 0x7F
}

fn simple_score(byte_counts: &[(u8, usize)]) -> u32 {
    // NOTE: This function assumes the inputs are already lowercased.
    for byte_count in byte_counts {
        // No control characters other than new line, CR or tab.
        if is_control(byte_count.0)
            && (byte_count.0 != b'\n' && byte_count.0 != b'\r' && byte_count.0 != b'\t')
        {
            return 0;
        }
    }

    // Very simple score: how many out of the top 7 characters include the most
    // common English characters.
    // English frequencies: 'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070, 'n': 0.067.
    // Note: Including space is SUPER important. Otherwise it won't work :)
    let most_freq = HashSet::from([b'e', b't', b'a', b'o', b'i', b'n', b' ']);

    // All scores that have no weird characters start with 1 (they're already better than the rest).
    let mut score = 1;
    for i in 0..most_freq.len() {
        if i >= byte_counts.len() {
            break;
        }
        if most_freq.contains(&byte_counts[i].0) {
            score += 1;
        }
    }
    score
}

pub fn find_best_key(bytes: &[u8]) -> (u8, u32) {
    let mut best_score = 0;
    let mut best_key = 0;
    for mask in 0_u8..=255_u8 {
        let decrypted = crate::encryption::sliding_xor(&bytes, &vec![mask]);
        match String::from_utf8(decrypted) {
            Err(_) => {
                continue;
            }
            Ok(mut decrypted_str) => {
                decrypted_str.make_ascii_lowercase();
                let counts = get_most_frequent_chars(&decrypted_str);
                let cur_score = simple_score(&counts);
                if cur_score > best_score {
                    best_score = cur_score;
                    best_key = mask;
                }
            }
        }
    }
    (best_key, best_score)
}
