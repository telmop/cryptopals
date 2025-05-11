use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::One;
use rand::Rng;

fn modexp_u32(base: u32, exp: u32, modulus: u32) -> u32 {
    let mut res = 1;
    let mut count = 0;
    while count < exp {
        res = (res * base) % modulus;
        count += 1;
    }
    res
}

fn modexp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let mut res = BigUint::one();
    let mut power = base.clone();
    for byte in exp.clone().to_bytes_le() {
        let mut mask = 1u8;
        for _ in 0..8 {
            if mask & byte != 0 {
                res = (res * &power) % modulus;
            }
            mask = mask << 1;
            power = power.pow(2) % modulus;
        }
    }
    res
}

#[allow(non_snake_case)]
fn challenge33() {
    // Small integers just to test the math.
    {
        let p: u32 = 37;
        let g: u32 = 5;
        let mut rng = rand::thread_rng();
        ();
        let a: u32 = rng.gen_range(0..p);
        let b: u32 = rng.gen_range(0..p);
        let A = modexp_u32(g, a, p);
        let B = modexp_u32(g, b, p);
        let private_key = modexp_u32(g, a * b, p);
        assert_eq!(private_key, modexp_u32(A, b, p));
        assert_eq!(private_key, modexp_u32(B, a, p));
    }

    let p = BigUint::parse_bytes(
        b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a0879\
        8e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0b\
        ff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55\
        d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c\
        08ca237327ffffffffffffffff",
        16,
    )
    .unwrap();
    let g = 2.to_biguint().unwrap();
    let mut rng = rand::thread_rng();
    ();
    let a = rng.gen_biguint_range(&BigUint::ZERO, &p);
    let b = rng.gen_biguint_range(&BigUint::ZERO, &p);
    let A = modexp(&g, &a, &p);
    let B = modexp(&g, &b, &p);
    let private_key = modexp(&g, &(&a * &b), &p);
    assert_eq!(private_key, modexp(&A, &b, &p));
    assert_eq!(private_key, modexp(&B, &a, &p));
    println!("Private key matches individual expectation.");
}

fn main() {
    let challenges = [challenge33];
    for (i, challenge) in challenges.iter().enumerate() {
        println!("Running challenge {}", i + 33);
        challenge();
    }
}

#[test]
fn test_modexp() {
    let base = 7.to_biguint().unwrap();
    let exp = 5.to_biguint().unwrap();
    // A large enough value so that it doesn't wrap around.
    let modulus = 20000.to_biguint().unwrap();
    let expected = 16807.to_biguint().unwrap();
    assert_eq!(expected, modexp(&base, &exp, &modulus));
}
