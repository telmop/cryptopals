use std::fmt::Write;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;
type Bytes = Vec<u8>;

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

pub fn b64encode(bytes: &Bytes) -> Result<String> {
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

pub fn hexstr_to_bytes(hex: &str) -> Result<Bytes> {
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

pub fn bytes_to_hexstr(bytes: &Bytes) -> String {
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn xor(bytes1: &Bytes, bytes2: &Bytes) -> Result<Bytes> {
    if bytes1.len() != bytes2.len() {
        return Err("Lengths must match!".into());
    }
    let mut output = Vec::with_capacity(bytes1.len());
    for i in 0..bytes1.len() {
        output.push(bytes1[i] ^ bytes2[i]);
    }
    Ok(output)
}

pub fn sliding_xor(message: &Bytes, mask: &Bytes) -> Bytes {
    assert!(mask.len() <= message.len());
    let mut result = Vec::with_capacity(message.len());
    for i in 0..message.len() {
        let mask_idx = i % mask.len();
        result.push(message[i] ^ mask[mask_idx]);
    }
    result
}
