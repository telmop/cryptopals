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
    let mut encoded = vec![];
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

pub fn hexstr_to_u8(hex: &str) -> Result<Vec<u8>> {
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
