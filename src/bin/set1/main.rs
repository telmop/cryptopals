fn challenge1() {
    let x = cryptopals::hexstr_to_u8("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
    let encoded = cryptopals::b64encode(&x).unwrap();
    assert_eq!(
        encoded,
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}

fn main() {
    challenge1();
}
