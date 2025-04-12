// https://en.wikipedia.org/wiki/Mersenne_Twister

const N: u32 = 624;
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
            cur_seed = F.wrapping_mul(cur_seed ^ (cur_seed >> (W - 2))) + i;
            state[i as usize] = cur_seed;
        }
        MT19937 { state, index: 0 }
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

        let mut y = x ^ (x >> U);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y ^ (y >> L)
    }
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
