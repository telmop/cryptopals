const BLOCK_SIZE: usize = 64;

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

    // From https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode
    pub fn compute(&self, bytes: &[u8]) -> [u8; 20] {
        let padded_bytes = if self.apply_padding {
            Self::pad_msg(bytes.to_vec(), None)
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
            let words = Sha1::get_words(&padded_bytes[block_idx..block_idx + BLOCK_SIZE]);

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
            let new_word =
                (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
            words.push(new_word);
        }
        words
    }
}

pub struct Md4 {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    apply_padding: bool,
}

impl Md4 {
    pub fn new() -> Self {
        Md4 {
            a: 0x67452301,
            b: 0xefcdab89,
            c: 0x98badcfe,
            d: 0x10325476,
            apply_padding: true,
        }
    }

    pub fn init(a: u32, b: u32, c: u32, d: u32) -> Self {
        Md4 {
            a,
            b,
            c,
            d,
            apply_padding: false,
        }
    }

    // From https://tools.ietf.org/html/rfc1320
    pub fn compute(&self, bytes: &[u8]) -> [u8; 16] {
        let padded_bytes = if self.apply_padding {
            Self::pad_msg(bytes.to_vec(), None)
        } else {
            assert_eq!((bytes.len() * 8) % 512, 0);
            bytes.to_vec()
        };

        let mut a: u32 = self.a;
        let mut b: u32 = self.b;
        let mut c: u32 = self.c;
        let mut d: u32 = self.d;

        // Read in 512 bit (64 bytes) blocks.
        for block_idx in (0..padded_bytes.len()).step_by(BLOCK_SIZE) {
            let words = Md4::get_words(&padded_bytes[block_idx..block_idx + BLOCK_SIZE]);

            // Lovely variable names. Again, from the spec.
            let aa: u32 = a;
            let bb: u32 = b;
            let cc: u32 = c;
            let dd: u32 = d;

            // Round 1.
            a = Md4::ff(a, b, c, d, words[0], 3);
            d = Md4::ff(d, a, b, c, words[1], 7);
            c = Md4::ff(c, d, a, b, words[2], 11);
            b = Md4::ff(b, c, d, a, words[3], 19);

            a = Md4::ff(a, b, c, d, words[4], 3);
            d = Md4::ff(d, a, b, c, words[5], 7);
            c = Md4::ff(c, d, a, b, words[6], 11);
            b = Md4::ff(b, c, d, a, words[7], 19);

            a = Md4::ff(a, b, c, d, words[8], 3);
            d = Md4::ff(d, a, b, c, words[9], 7);
            c = Md4::ff(c, d, a, b, words[10], 11);
            b = Md4::ff(b, c, d, a, words[11], 19);

            a = Md4::ff(a, b, c, d, words[12], 3);
            d = Md4::ff(d, a, b, c, words[13], 7);
            c = Md4::ff(c, d, a, b, words[14], 11);
            b = Md4::ff(b, c, d, a, words[15], 19);

            // Round 2.
            a = Md4::gg(a, b, c, d, words[0], 3);
            d = Md4::gg(d, a, b, c, words[4], 5);
            c = Md4::gg(c, d, a, b, words[8], 9);
            b = Md4::gg(b, c, d, a, words[12], 13);

            a = Md4::gg(a, b, c, d, words[1], 3);
            d = Md4::gg(d, a, b, c, words[5], 5);
            c = Md4::gg(c, d, a, b, words[9], 9);
            b = Md4::gg(b, c, d, a, words[13], 13);

            a = Md4::gg(a, b, c, d, words[2], 3);
            d = Md4::gg(d, a, b, c, words[6], 5);
            c = Md4::gg(c, d, a, b, words[10], 9);
            b = Md4::gg(b, c, d, a, words[14], 13);

            a = Md4::gg(a, b, c, d, words[3], 3);
            d = Md4::gg(d, a, b, c, words[7], 5);
            c = Md4::gg(c, d, a, b, words[11], 9);
            b = Md4::gg(b, c, d, a, words[15], 13);

            // Round 3.
            a = Md4::hh(a, b, c, d, words[0], 3);
            d = Md4::hh(d, a, b, c, words[8], 9);
            c = Md4::hh(c, d, a, b, words[4], 11);
            b = Md4::hh(b, c, d, a, words[12], 15);

            a = Md4::hh(a, b, c, d, words[2], 3);
            d = Md4::hh(d, a, b, c, words[10], 9);
            c = Md4::hh(c, d, a, b, words[6], 11);
            b = Md4::hh(b, c, d, a, words[14], 15);

            a = Md4::hh(a, b, c, d, words[1], 3);
            d = Md4::hh(d, a, b, c, words[9], 9);
            c = Md4::hh(c, d, a, b, words[5], 11);
            b = Md4::hh(b, c, d, a, words[13], 15);

            a = Md4::hh(a, b, c, d, words[3], 3);
            d = Md4::hh(d, a, b, c, words[11], 9);
            c = Md4::hh(c, d, a, b, words[7], 11);
            b = Md4::hh(b, c, d, a, words[15], 15);

            a = a.wrapping_add(aa);
            b = b.wrapping_add(bb);
            c = c.wrapping_add(cc);
            d = d.wrapping_add(dd);
        }
        let mut result = [0u8; 16];
        result[0..4].copy_from_slice(&a.to_le_bytes());
        result[4..8].copy_from_slice(&b.to_le_bytes());
        result[8..12].copy_from_slice(&c.to_le_bytes());
        result[12..16].copy_from_slice(&d.to_le_bytes());
        result
    }

    // Auxiliary functions. Same names as in the spec.
    fn f(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | ((!x) & z)
    }
    fn g(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (x & z) | (y & z)
    }
    fn h(x: u32, y: u32, z: u32) -> u32 {
        x ^ y ^ z
    }

    // Round functions. Again, names from the spec.
    fn ff(a: u32, b: u32, c: u32, d: u32, x_k: u32, s: u32) -> u32 {
        a.wrapping_add(Md4::f(b, c, d))
            .wrapping_add(x_k)
            .rotate_left(s)
    }
    fn gg(a: u32, b: u32, c: u32, d: u32, x_k: u32, s: u32) -> u32 {
        a.wrapping_add(Md4::g(b, c, d))
            .wrapping_add(x_k)
            .wrapping_add(0x5A827999)
            .rotate_left(s)
    }
    fn hh(a: u32, b: u32, c: u32, d: u32, x_k: u32, s: u32) -> u32 {
        a.wrapping_add(Md4::h(b, c, d))
            .wrapping_add(x_k)
            .wrapping_add(0x6ED9EBA1)
            .rotate_left(s)
    }

    fn get_words(block: &[u8]) -> Vec<u32> {
        let mut words: Vec<u32> = vec![];
        for word_idx in (0..BLOCK_SIZE).step_by(4) {
            // 16 32 bit words.
            words.push(u32::from_le_bytes(
                block[word_idx..word_idx + 4].try_into().unwrap(),
            ));
        }
        words
    }

    pub fn pad_msg(mut msg: Vec<u8>, msg_len: Option<u64>) -> Vec<u8> {
        let length = match msg_len {
            None => (msg.len() * 8) as u64,
            Some(value) => value,
        };
        msg.push(0x80u8);
        while (msg.len() * 8) % 512 != 448 {
            msg.push(0);
        }
        msg.extend(length.to_le_bytes());
        msg
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
    let padded_msg = Sha1::pad_msg("asdf".as_bytes().to_vec(), None);
    let sha1_hash = sha1.compute(&padded_msg);
    assert_eq!(
        sha1_hash,
        hex_literal::hex!("3da541559918a808c2402bba5012f6c60b27661c")
    );
}

#[test]
fn test_md4() {
    let md4 = Md4::new();
    let md4_hash = md4.compute("asdf".as_bytes());
    assert_eq!(
        md4_hash,
        hex_literal::hex!("970d28f4dd477bc184fbd10b376de753")
    );
}
