const BLOCK_SIZE: usize = 64;

pub fn pad_msg(mut msg: Vec<u8>, msg_len: Option<u64>) -> Vec<u8> {
    let length = match msg_len {
        None => (msg.len() * 8) as u64,
        Some(value) => value,
    };
    msg.push(0x80u8);
    while (msg.len() * 8) % 512 != 448 {
        msg.push(0);
    }
    msg.extend(length.to_be_bytes());
    msg
}

fn get_words(block: &[u8]) -> Vec<u32> {
    let mut words: Vec<u32> = vec![];
    for word_idx in (0..BLOCK_SIZE).step_by(4) {
        // 16 32 bit words.
        words.push(u32::from_be_bytes(
            block[word_idx..word_idx + 4].try_into().unwrap(),
        ));
    }

    // Expand 16 words (64 / 4) into 80.
    for i in 16..80 {
        let new_word = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        words.push(new_word);
    }
    words
}

pub struct Sha1 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
    apply_padding: bool,
}

impl Sha1 {
    pub fn new() -> Self {
        Sha1 {
            h0: 0x67452301,
            h1: 0xEFCDAB89,
            h2: 0x98BADCFE,
            h3: 0x10325476,
            h4: 0xC3D2E1F0,
            apply_padding: true,
        }
    }

    pub fn init(h0: u32, h1: u32, h2: u32, h3: u32, h4: u32) -> Self {
        Sha1 {
            h0,
            h1,
            h2,
            h3,
            h4,
            apply_padding: false,
        }
    }

    // From https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
    pub fn compute(&self, bytes: &[u8]) -> [u8; 20] {
        let padded_bytes = if self.apply_padding {
            pad_msg(bytes.to_vec(), None)
        } else {
            assert_eq!((bytes.len() * 8) % 512, 0);
            bytes.to_vec()
        };
        let mut h0: u32 = self.h0;
        let mut h1: u32 = self.h1;
        let mut h2: u32 = self.h2;
        let mut h3: u32 = self.h3;
        let mut h4: u32 = self.h4;

        // Read in 512 bit (64 bytes) blocks.
        for block_idx in (0..padded_bytes.len()).step_by(BLOCK_SIZE) {
            let words: Vec<u32> = get_words(&padded_bytes[block_idx..block_idx + BLOCK_SIZE]);

            let mut a = h0;
            let mut b = h1;
            let mut c = h2;
            let mut d = h3;
            let mut e = h4;

            for i in 0..80 {
                let (f, k): (u32, u32) = if i < 20 {
                    ((b & c) | ((!b) & d), 0x5A827999)
                } else if i >= 20 && i < 40 {
                    (b ^ c ^ d, 0x6ED9EBA1)
                } else if i >= 40 && i < 60 {
                    ((b & c) ^ (b & d) ^ (c & d), 0x8F1BBCDC)
                } else {
                    assert!(i < 80);
                    (b ^ c ^ d, 0xCA62C1D6)
                };
                let tmp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(words[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = tmp;
            }

            h0 = h0.wrapping_add(a);
            h1 = h1.wrapping_add(b);
            h2 = h2.wrapping_add(c);
            h3 = h3.wrapping_add(d);
            h4 = h4.wrapping_add(e);
        }
        let mut result = [0u8; 20];
        result[0..4].copy_from_slice(&h0.to_be_bytes());
        result[4..8].copy_from_slice(&h1.to_be_bytes());
        result[8..12].copy_from_slice(&h2.to_be_bytes());
        result[12..16].copy_from_slice(&h3.to_be_bytes());
        result[16..20].copy_from_slice(&h4.to_be_bytes());
        result
    }
}

#[test]
fn test_sha1() {
    let sha1 = Sha1::new();
    let sha1_hash = sha1.compute("asdf".as_bytes());
    assert_eq!(
        sha1_hash,
        hex_literal::hex!("3da541559918a808c2402bba5012f6c60b27661c")
    );
}

#[test]
fn test_sha1_init() {
    let sha1 = Sha1::init(0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0);
    let padded_msg = pad_msg("asdf".as_bytes().to_vec(), None);
    let sha1_hash = sha1.compute(&padded_msg);
    assert_eq!(
        sha1_hash,
        hex_literal::hex!("3da541559918a808c2402bba5012f6c60b27661c")
    );
}
