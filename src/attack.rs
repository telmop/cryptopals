use std::collections::HashMap;
use std::collections::HashSet;

pub enum Score {
    Simple,
    Quadratic,
}

fn get_char_counts(s: &[u8]) -> Vec<(u8, usize)> {
    let mut counts = HashMap::new();
    for c in s {
        *counts.entry(*c).or_insert(0) += 1;
    }

    let mut items: Vec<(u8, usize)> = counts.into_iter().collect();
    // items.sort_by(|a, b| b.1.cmp(&a.1)); // Reverse order.
    items.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items
}

fn is_control(u: u8) -> bool {
    u < 0x20 || u == 0x7F
}

fn simple_score(decrypted: &[u8]) -> u32 {
    let mut decrypted_vec = decrypted.to_vec();
    decrypted_vec.make_ascii_lowercase();
    let counts = get_char_counts(&decrypted_vec);
    if !decrypted_vec.is_ascii() {
        return 0;
    }

    if decrypted_vec.iter().any(|&c| is_control(c) && c != b'\n') {
        return 0;
    }

    // Very simple score: how many out of the top 7 characters include the most
    // common English characters.
    // English frequencies: 'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070, 'n': 0.067.
    // Note: Including space is SUPER important. Otherwise it won't work :)
    let most_freq = HashSet::from([b'e', b't', b'a', b'o', b'i', b'n', b' ']);

    // All scores that have no weird characters start with 1 (they're already better than the rest).
    let mut score = 1;
    for i in 0..most_freq.len() {
        if i >= counts.len() {
            break;
        }
        if most_freq.contains(&counts[i].0) {
            score += 1;
        }
    }
    score
}

// Lee, E. Stewart. "Essays about Computer Security" (PDF). University of Cambridge Computer Laboratory. p. 181.
static CHAR_FREQS: [(u8, f32); 28] = [
    (b' ', 0.1217),
    (b'e', 0.1136),
    (b't', 0.0803),
    (b'.', 0.0657),
    (b'a', 0.0609),
    (b'o', 0.0600),
    (b's', 0.0568),
    (b'i', 0.0544),
    (b'n', 0.0544),
    (b'r', 0.0495),
    (b'h', 0.0341),
    (b'd', 0.0292),
    (b'l', 0.0292),
    (b'c', 0.0284),
    (b'm', 0.0276),
    (b'u', 0.0243),
    (b'p', 0.0195),
    (b'f', 0.0179),
    (b'g', 0.0138),
    (b'w', 0.0138),
    (b'y', 0.0130),
    (b'b', 0.0105),
    (b'v', 0.0097),
    (b'k', 0.0041),
    (b'j', 0.0024),
    (b'q', 0.0024),
    (b'x', 0.0024),
    (b'z', 0.0003),
];

fn is_alphabetic(u: u8) -> bool {
    (u >= 0x41 && u <= 0x5A) || (u >= 0x61 && u <= 0x7A)
}

fn is_numeric(u: u8) -> bool {
    u >= b'0' && u <= b'9'
}

fn is_alphanumeric(u: u8) -> bool {
    is_alphabetic(u) || is_numeric(u)
}

// Replace white space with ' ', and other chars with '.'.
fn get_transformed_counts(v: &[u8]) -> HashMap<u8, f32> {
    let mut counts: HashMap<u8, f32> = HashMap::new();
    for &c in v {
        if is_control(c) {
            continue;
        }
        let key = if is_alphabetic(c) {
            c.to_ascii_lowercase()
        } else if c == b' ' || c == b'\t' || c == b'\r' {
            b' '
        } else {
            b'.'
        };
        let count = counts.entry(key).or_insert(0f32);
        *count += 1f32;
    }
    counts
}

fn quadratic_score(decrypted: &[u8]) -> u32 {
    let decrypted_vec = decrypted.to_vec();

    if !decrypted_vec.is_ascii() {
        return 0;
    }

    if decrypted_vec.iter().any(|&c| is_control(c) && c != b'\n') {
        return 0;
    }
    // Hacky, as it's not generally valid.
    let special_chars = b"!\"$',-./:;? \t\n\r";
    if decrypted_vec
        .iter()
        .any(|&c| !is_alphanumeric(c) && !special_chars.contains(&c))
    {
        return 0;
    }

    let counts = get_transformed_counts(&decrypted_vec);
    let mut score = 0;
    let str_len = decrypted_vec.len() as f32;
    for char_freq in &CHAR_FREQS {
        let (c, f) = char_freq;
        let expected = f * str_len;
        let actual = *counts.get(c).unwrap_or(&0f32);
        score += (expected - actual).powi(2) as u32;
    }
    std::u32::MAX - score
}

pub fn find_best_key(bytes: &[u8], score_type: Score) -> (u8, u32) {
    let mut best_score = 0;
    let mut best_key = 0;
    for mask in 0_u8..=255_u8 {
        let decrypted = crate::encryption::sliding_xor(&bytes, &vec![mask]);
        let cur_score = match score_type {
            Score::Simple => simple_score(&decrypted),
            Score::Quadratic => quadratic_score(&decrypted),
        };
        if cur_score > best_score {
            best_score = cur_score;
            best_key = mask;
        }
    }
    (best_key, best_score)
}
