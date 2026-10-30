/// Reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

const INITIAL_HASH_VALUE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub(crate) struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: INITIAL_HASH_VALUE,
            buffer: [0; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    pub(crate) fn hash(data: &[u8]) -> [u8; 32] {
        let mut s = Self::new();
        s.update(data);
        s.finalize()
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.total_len += data.len() as u64;

        // keep anything left over in the buffer from a previous update call
        if self.buffer_len > 0 {
            let take_len = usize::min(64 - self.buffer_len, data.len());
            self.buffer[self.buffer_len..self.buffer_len + take_len]
                .copy_from_slice(&data[..take_len]);
            self.buffer_len += take_len;
            data = &data[take_len..];
            if self.buffer_len < 64 {
                return;
            }
            Self::compress(&mut self.state, &self.buffer);
            self.buffer_len = 0;
        }

        while data.len() >= 64 {
            self.buffer.copy_from_slice(&data[..64]);
            self.buffer_len = 64;
            data = &data[64..];
            Self::compress(&mut self.state, &self.buffer);
            self.buffer_len = 0;
        }

        // stash what ever data is left for future call or finalize
        self.buffer[..data.len()].copy_from_slice(&data);
        self.buffer_len = data.len();
    }

    pub(crate) fn finalize(&self) -> [u8; 32] {
        let mut state = self.state.clone();
        let mut data = self.buffer.clone();
        let mut pos = self.buffer_len;
        data[pos] = 0x80;
        pos += 1;
        while pos != 56 {
            if pos == data.len() {
                Self::compress(&mut state, &data);
                pos = 0;
            }
            data[pos] = 0x00;
            pos += 1;
        }
        let len_bytes = (self.total_len * 8).to_be_bytes();
        data[56..].copy_from_slice(&len_bytes);
        Self::compress(&mut state, &data);
        let mut digest = [0u8; 32];
        for i in 0..8 {
            let bytes = state[i].to_be_bytes();
            digest[i * 4] = bytes[0];
            digest[i * 4 + 1] = bytes[1];
            digest[i * 4 + 2] = bytes[2];
            digest[i * 4 + 3] = bytes[3];
        }
        digest
    }

    fn compress(state: &mut [u32; 8], data: &[u8]) {
        let mut words = [0u32; 64];
        for t in 0..16 {
            let mut word_bytes = [0u8; 4];
            word_bytes.copy_from_slice(&data[(t * 4)..(t * 4 + 4)]);
            let word = u32::from_be_bytes(word_bytes);
            words[t] = word;
        }
        for t in 16..64 {
            let w0 = Self::sigma1(words[t - 2]);
            let w1 = words[t - 7];
            let w2 = Self::sigma0(words[t - 15]);
            let w3 = words[t - 16];
            let word = u32::wrapping_add(w0, u32::wrapping_add(w1, u32::wrapping_add(w2, w3)));
            words[t] = word;
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for t in 0..64 {
            let t1 = u32::wrapping_add(
                h,
                u32::wrapping_add(
                    Self::big_sigma1(e),
                    u32::wrapping_add(
                        Self::ch(e, f, g),
                        u32::wrapping_add(ROUND_CONSTANTS[t], words[t]),
                    ),
                ),
            );
            let t2 = u32::wrapping_add(Self::big_sigma0(a), Self::maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = u32::wrapping_add(d, t1);
            d = c;
            c = b;
            b = a;
            a = u32::wrapping_add(t1, t2);
        }
        state[0] = u32::wrapping_add(state[0], a);
        state[1] = u32::wrapping_add(state[1], b);
        state[2] = u32::wrapping_add(state[2], c);
        state[3] = u32::wrapping_add(state[3], d);
        state[4] = u32::wrapping_add(state[4], e);
        state[5] = u32::wrapping_add(state[5], f);
        state[6] = u32::wrapping_add(state[6], g);
        state[7] = u32::wrapping_add(state[7], h);
    }

    fn sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    fn sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    fn big_sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    fn big_sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }
}

/// Reference: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abc_sample() {
        let mut hasher = Sha256::new();

        hasher.update(b"abc");
        let digest = hasher.finalize();

        assert_eq!(
            digest,
            to_bytes([
                0xBA7816BF, 0x8F01CFEA, 0x414140DE, 0x5DAE2223, 0xB00361A3, 0x96177A9C, 0xB410FF61,
                0xF20015AD,
            ])
        );
    }

    #[test]
    fn two_block_message_sample() {
        let mut hasher = Sha256::new();

        hasher.update(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        let digest = hasher.finalize();

        assert_eq!(
            digest,
            to_bytes([
                0x248D6A61, 0xD20638B8, 0xE5C02693, 0x0C3E6039, 0xA33CE459, 0x64FF2167, 0xF6ECEDD4,
                0x19DB06C1
            ])
        );
    }

    fn to_bytes(state: [u32; 8]) -> [u8; 32] {
        let mut digest = [0u8; 32];
        for i in 0..8 {
            let bytes = state[i].to_be_bytes();
            digest[i * 4] = bytes[0];
            digest[i * 4 + 1] = bytes[1];
            digest[i * 4 + 2] = bytes[2];
            digest[i * 4 + 3] = bytes[3];
        }
        digest
    }
}
