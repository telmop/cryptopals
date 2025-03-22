fn challenge1() {
    let x = cryptopals::hexstr_to_bytes("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    let encoded = cryptopals::b64encode(&x).unwrap();
    assert_eq!(
        encoded,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}

fn challenge2() {
    let vec1 = cryptopals::hexstr_to_bytes("1c0111001f010100061a024b53535009181c").unwrap();
    let vec2 = cryptopals::hexstr_to_bytes("686974207468652062756c6c277320657965").unwrap();
    let result = cryptopals::xor(&vec1, &vec2).unwrap();
    let result_str = cryptopals::bytes_to_hexstr(&result);
    assert_eq!(result_str, "746865206b696420646f6e277420706c6179");
}

fn main() {
    println!("Running challenge 1");
    challenge1();

    println!("Running challenge 2");
    challenge2();
}
