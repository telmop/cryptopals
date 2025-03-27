use std::fmt::Write;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

fn byte_to_b64ascii(byte: u8) -> u8 {
    match byte {
        0..=25 => b'A' + byte,
        26..=51 => b'a' + (byte - 26),
        52..=61 => b'0' + (byte - 52),
        62 => b'+',
        63 => b'/',
        _ => panic!("This can't happen"),
    }
}

pub fn b64encode(bytes: &[u8]) -> Result<String> {
    let mut encoded = vec![]; // TODO: Switch to with_capacity.
    let mut buf: u8 = 0;
    for (i, b) in bytes.iter().enumerate() {
        let is_last = i == bytes.len() - 1;
        match i % 3 {
            0 => {
                // First 6 for now, last two for next character.
                encoded.push(byte_to_b64ascii((b & 0b1111_1100) >> 2));
                buf = b & 0b11;
                if is_last {
                    encoded.append(&mut vec![byte_to_b64ascii(buf << 4), b'=', b'=']);
                }
            }
            1 => {
                // 4 now, 4 next.
                encoded.push(byte_to_b64ascii((buf << 4) + ((b & 0b1111_0000) >> 4)));
                buf = b & 0b1111;
                if is_last {
                    encoded.append(&mut vec![byte_to_b64ascii(buf << 2), b'=']);
                }
            }
            2 => {
                // 2 now, 6 later.
                encoded.push(byte_to_b64ascii((buf << 2) + ((b & 0b1100_0000) >> 6)));
                encoded.push(byte_to_b64ascii(b & 0b11_1111));
                buf = 0;
            }
            _ => panic!("This can't happen"),
        }
    }
    Ok(String::from_utf8(encoded)?)
}

fn b64ascii_to_byte(ascii: u8) -> (u8, bool) {
    // Returns the respective value for each base64 character.
    // The boolean describes whether it is a padding value ('=') or not.
    match ascii {
        b'=' => (0, true),
        b'A'..=b'Z' => (ascii - b'A', false),
        b'a'..=b'z' => (ascii - b'a' + 26, false),
        b'0'..=b'9' => (ascii - b'0' + 52, false),
        b'+' => (62, false),
        b'/' => (63, false),
        _ => panic!("This can't happen"),
    }
}

pub fn b64decode(encoded: &str) -> Result<Vec<u8>> {
    // 1110_1101 0010_1001 0000_1111
    // 111011 01_0010 1001_00 001111
    let mut buf: u8 = 0;
    let mut decoded: Vec<u8> = vec![]; // TODO: Switch to with_capacity.
    for (i, b) in encoded.as_bytes().into_iter().enumerate() {
        match i % 4 {
            0 => {
                let (value, is_padding) = b64ascii_to_byte(*b);
                if is_padding {
                    // Can't have padding at the beginning of a cycle.
                    return Err("Invalid base64 string".into());
                }
                buf = value << 2;
            }
            1 => {
                let (value, is_padding) = b64ascii_to_byte(*b);
                if is_padding {
                    // Can't have padding at this stage of the cycle.
                    return Err("Invalid base64 string".into());
                }
                decoded.push(buf + ((value & 0b110000) >> 4));
                buf = (value & 0b1111) << 4;
            }
            2 => {
                let (value, is_padding) = b64ascii_to_byte(*b);
                if is_padding {
                    break;
                }
                decoded.push(buf + ((value & 0b111100) >> 2));
                buf = (value & 0b11) << 6;
            }
            3 => {
                let (value, is_padding) = b64ascii_to_byte(*b);
                if is_padding {
                    break;
                }
                decoded.push(buf + value);
                buf = 0;
            }
            _ => panic!("Impossible"),
        }
    }
    Ok(decoded)
}

pub fn hexstr_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let mut s = hex.to_string();
    if s.len() % 2 == 1 {
        s.insert(0, '0');
    }
    let mut result = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)?;
        result.push(byte);
    }
    Ok(result)
}

pub fn bytes_to_hexstr(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn from_base64_file(filename: &Path) -> Result<Vec<u8>> {
    let f = File::open(filename).expect("Couldn't open file");
    let mut reader = BufReader::new(f);
    let mut encoded = String::new();
    let _ = reader.read_to_string(&mut encoded);
    // Remove new lines, if any.
    encoded = encoded.replace("\r\n", "").replace("\n", "");
    b64decode(&encoded)
}

// ***** TESTS *****

#[test]
fn test_base64_identity() {
    let test_cases = vec!["M", "Ma", "Man", "Many things"];
    for test_case in test_cases {
        let bytes = test_case.as_bytes();
        let encoded = b64encode(bytes).unwrap();
        let decoded = b64decode(&encoded).unwrap();
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(test_case, decoded_str);
    }
}
