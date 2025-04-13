// https://en.wikipedia.org/wiki/Mersenne_Twister

pub const N: u32 = 624;
const M: u32 = 397;
const W: u32 = 32;
const R: u32 = 31;
const UMASK: u32 = 0xffffffff << R;
const LMASK: u32 = 0xffffffff >> (W - R);
const A: u32 = 0x9908b0df;
const U: u32 = 11;
const S: u32 = 7;
const T: u32 = 15;
const L: u32 = 18;
const B: u32 = 0x9d2c5680;
const C: u32 = 0xefc60000;
const F: u32 = 1812433253;

pub struct MT19937 {
    state: [u32; N as usize],
    index: usize,
}

impl MT19937 {
    pub fn new(seed: u32) -> Self {
        let mut state = [0u32; N as usize];
        let mut cur_seed = seed;
        state[0] = cur_seed;
        for i in 1..N {
            cur_seed = F
                .wrapping_mul(cur_seed ^ (cur_seed >> (W - 2)))
                .wrapping_add(i);
            state[i as usize] = cur_seed;
        }
        MT19937 { state, index: 0 }
    }

    pub fn empty() -> Self {
        MT19937 {
            state: [0u32; N as usize],
            index: 0,
        }
    }

    fn temper(&self, x: u32) -> u32 {
        let mut y = x ^ (x >> U); // xor_right.
        y = y ^ ((y << S) & B); // xor_left_and.
        y = y ^ ((y << T) & C); // xor_left_and.
        y ^ (y >> L) // xor_right.
    }

    fn untemper(&self, y: u32) -> u32 {
        /* There are two kinds of operations:
            1. y = x ^ (x >> c) - we'll call xor_right.
            2. y = x ^ ((x << c1) & c2) - we'll call xor_left_and.
        To "untemper" we need to invert each and in reverse order of what `temper` does.
        */
        let mut x = undo_xor_right(y, L);
        x = undo_xor_left_and(x, T, C);
        x = undo_xor_left_and(x, S, B);
        undo_xor_right(x, U)
    }

    pub fn reconstruct_state(&mut self, value: u32) {
        self.state[self.index] = self.untemper(value);
        self.index += 1;
        if self.index >= N as usize {
            self.index = 0;
        }
    }

    pub fn random(&mut self) -> u32 {
        let mut k = self.index;
        let mut j: i32 = (k as i32) - (N - 1) as i32;
        if j < 0 {
            j += N as i32;
        }
        let mut x = (self.state[k] & UMASK) | (self.state[j as usize] & LMASK);
        let mut x_a = x >> 1;
        if x & 0x01 > 0 {
            x_a ^= A;
        }
        j = k as i32 - (N - M) as i32;
        if j < 0 {
            j += N as i32;
        }
        x = self.state[j as usize] ^ x_a;
        self.state[k] = x;
        k += 1;

        if k >= N as usize {
            k = 0;
        }
        self.index = k;
        self.temper(x)
    }
}

// Gets the bits from [start, start + count[.
// Might look strange, but it's pretty trivial if you think about it.
fn get_bits(value: u32, start: u32, count: u32) -> u32 {
    assert!(start + count <= 32);
    // Create a mask with `count` ones as the least significant bits.
    let mask = u32::MAX >> (32 - count);
    // Shift bits so that [start, start + count[ are the least significant bits.
    (value >> (32 - start - count)) & mask
}

// Undoes the operation: y = x ^ (x >> c).
fn undo_xor_right(y: u32, c: u32) -> u32 {
    // The first `c` bits  stay unchanged.
    let mut x = get_bits(y, 0, c);
    let mut previous_bits = x;
    for i in (c..32).step_by(c as usize) {
        // How many bits we can read on the current iteration. Always `c`, except possibly on the last.
        let available_bits = if i + c > 32 { 32 - i } else { c };
        // These bits needs were xored with the bits from x. We don't know all the bits from x,
        // which is why we do this for loop - so we can reconstruct x as we learn its most sig. bits.
        let bits = get_bits(y, i, available_bits);
        previous_bits >>= c - available_bits; // On the last round we need to xor with less than `c` bits.
        previous_bits ^= bits;
        x = (x << available_bits) ^ previous_bits;
    }
    x
}

// Undoes the operation: y = x ^ ((x << c1) & c2).
fn undo_xor_left_and(y: u32, c1: u32, c2: u32) -> u32 {
    // The last `c1` bits stay unchanged.
    let mut x = get_bits(y, 32 - c1, c1);
    let mut previous_bits = x;
    for i in (0..=(32 - c1)).rev().step_by(c1 as usize) {
        // Where to start reading and how many bits. Usually, `i - c1` and `c1`, respectively.
        // On the last iteration it can be 0 and `i`.
        let (start, available_bits) = if c1 > i { (0, i) } else { (i - c1, c1) };
        // These bits needs were xored with the bits from x. We don't know all the bits from x,
        // which is why we do this for loop - so we can reconstruct x as we learn its least sig. bits.
        let bits = get_bits(y, start, available_bits);
        if available_bits < c1 {
            // Drop the `c1 - available_bits` most significant bits on the last iteration.
            let mask = (1 << available_bits) - 1;
            previous_bits &= mask;
        }

        // Since get_bits shifts the bits right, we need to shift c2 as well.
        previous_bits = bits ^ (previous_bits & (c2 >> (32 - i)));
        x = (previous_bits << (32 - i)) ^ x;
    }
    x
}

#[test]
fn test_mt19937() {
    let mut rng = MT19937::new(0);
    assert_eq!(rng.random(), 2357136044);
    for _ in 0..100 {
        rng.random();
    }
    assert_eq!(rng.random(), 165035946);
}

#[test]
fn test_mt19937_recommended_seed() {
    let mut rng = MT19937::new(19650218);
    assert_eq!(rng.random(), 2325592414);
    for _ in 0..100 {
        rng.random();
    }
    assert_eq!(rng.random(), 2879021126);
}

#[test]
fn test_temper_untemper() {
    let rng = MT19937::new(0); // Seed doesn't matter.
    let x1 = 2347862485;
    assert_eq!(rng.untemper(rng.temper(x1)), x1);

    let x2 = 19650218;
    assert_eq!(rng.untemper(rng.temper(x2)), x2);
}
