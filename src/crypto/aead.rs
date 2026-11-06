/// Reference: https://www.rfc-editor.org/info/rfc8439/
use anyhow::{Context, Error, bail};

type State = [[u32; 4]; 4];

pub(crate) fn chacha20_aead_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), Error> {
    let otk = poly1305_key_gen(key, nonce);
    let ciphertext = chacha20_encrypt(key, nonce, plaintext, 1)?;
    let mut mac_data = pad_16(aad);
    mac_data.append(&mut pad_16(&ciphertext));
    mac_data.append(&mut u64::try_from(aad.len())?.to_le_bytes().to_vec());
    mac_data.append(&mut u64::try_from(ciphertext.len())?.to_le_bytes().to_vec());
    let tag = poly1305_mac(&otk, &mac_data);
    Ok((ciphertext, tag))
}

pub(crate) fn chacha20_aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let otk = poly1305_key_gen(key, nonce);
    let plaintext = chacha20_encrypt(key, nonce, ciphertext, 1)?;
    let mut mac_data = pad_16(aad);
    mac_data.append(&mut pad_16(&ciphertext));
    mac_data.append(&mut u64::try_from(aad.len())?.to_le_bytes().to_vec());
    mac_data.append(&mut u64::try_from(ciphertext.len())?.to_le_bytes().to_vec());
    let out_tag = poly1305_mac(&otk, &mac_data);
    // RFC calls out that timing differences on how quickly a bad tag is rejected can leak info
    // and enable tag-forgery attacks.
    // Following ensure a constant time comparison regardless of an initial byte difference being discovered.
    let diff = tag
        .iter()
        .zip(out_tag.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    if diff != 0 {
        bail!("produced invalid tag");
    }
    Ok(plaintext)
}

fn chacha20_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    counter: u32,
) -> Result<Vec<u8>, Error> {
    const BLOCK_SIZE: usize = 64;
    let mut msg = Vec::with_capacity(plaintext.len());
    let num_blocks = plaintext.len() / BLOCK_SIZE;
    for j in 0..num_blocks {
        let block_counter = counter.checked_add(j.try_into()?).context("")?;
        let key_stream = chacha20_block(key, nonce, block_counter);
        let block: &[u8; BLOCK_SIZE] =
            &plaintext[j * BLOCK_SIZE..j * BLOCK_SIZE + BLOCK_SIZE].try_into()?;
        for n in 0..BLOCK_SIZE {
            msg.push(block[n] ^ key_stream[n]);
        }
    }
    if plaintext.len() % BLOCK_SIZE != 0 {
        let block_counter = counter.checked_add(num_blocks.try_into()?).context("")?;
        let key_stream = chacha20_block(key, nonce, block_counter);
        let block = &plaintext[num_blocks * BLOCK_SIZE..];
        for n in 0..block.len() {
            msg.push(block[n] ^ key_stream[n]);
        }
    }
    Ok(msg)
}

fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut state: State = [
        [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574],
        [0x00000000; 4],
        [0x00000000; 4],
        [0x00000000; 4],
    ];

    for i in 0..8 {
        let b_word: [u8; 4] = key[i * 4..i * 4 + 4].try_into().unwrap();
        let word = u32::from_le_bytes(b_word);
        state[1 + i / 4][i % 4] = word;
    }

    state[3][0] = counter;
    for i in 0..3 {
        let b_word: [u8; 4] = nonce[i * 4..i * 4 + 4].try_into().unwrap();
        let word = u32::from_le_bytes(b_word);
        state[3][i + 1] = word;
    }

    let initial_state = state;

    for _ in 0..10 {
        chacha_state_quarter_round(&mut state, 0, 4, 8, 12);
        chacha_state_quarter_round(&mut state, 1, 5, 9, 13);
        chacha_state_quarter_round(&mut state, 2, 6, 10, 14);
        chacha_state_quarter_round(&mut state, 3, 7, 11, 15);
        chacha_state_quarter_round(&mut state, 0, 5, 10, 15);
        chacha_state_quarter_round(&mut state, 1, 6, 11, 12);
        chacha_state_quarter_round(&mut state, 2, 7, 8, 13);
        chacha_state_quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut block = [0u8; 64];
    for i in 0..4 {
        for j in 0..4 {
            let word = u32::wrapping_add(initial_state[i][j], state[i][j]);
            let b_word = word.to_le_bytes();
            let slot = i * 16 + j * 4; // find our place in the serialized slice
            block[slot..slot + 4].copy_from_slice(&b_word);
        }
    }

    block
}

fn chacha_state_quarter_round(state: &mut State, x: usize, y: usize, z: usize, w: usize) {
    let a = state[x / 4][x % 4];
    let b = state[y / 4][y % 4];
    let c = state[z / 4][z % 4];
    let d = state[w / 4][w % 4];
    let (a, b, c, d) = chacha_quarter_round(a, b, c, d);
    state[x / 4][x % 4] = a;
    state[y / 4][y % 4] = b;
    state[z / 4][z % 4] = c;
    state[w / 4][w % 4] = d;
}

fn chacha_quarter_round(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a = u32::wrapping_add(a, b);
    let d = d ^ a;
    let d = u32::rotate_left(d, 16);
    let c = u32::wrapping_add(c, d);
    let b = b ^ c;
    let b = u32::rotate_left(b, 12);
    let a = u32::wrapping_add(a, b);
    let d = d ^ a;
    let d = u32::rotate_left(d, 8);
    let c = u32::wrapping_add(c, d);
    let b = b ^ c;
    let b = u32::rotate_left(b, 7);
    (a, b, c, d)
}

fn poly1305_key_gen(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let counter = 0;
    let block = chacha20_block(key, nonce, counter);
    block[0..32].try_into().unwrap()
}

// uses a "limb" accumulator strategy that splits
// into 26 bit limbs stored in u32's to handle
// math > 2^26 needed for this algorithm
fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let r_bytes: [u8; 16] = key[0..16].try_into().unwrap();
    let mut r_int = u128::from_le_bytes(r_bytes);
    r_int = r_int & 0x0ffffffc0ffffffc0ffffffc0fffffff; // clamp
    let s_bytes: [u8; 16] = key[16..].try_into().unwrap();
    let s = u128::from_le_bytes(s_bytes);
    let r = split_into_limbs(r_int);
    let mut a = [0x00u32; 5];
    let num_blocks = msg.len().div_ceil(16);
    for i in 0..num_blocks {
        // extract n from msg
        let start = i * 16;
        let end = usize::min(i * 16 + 16, msg.len());
        let mut block: [u8; 16] = [0u8; 16];
        block[..end - start].copy_from_slice(&msg[start..end]);
        let n_int = u128::from_le_bytes(block);
        let mut n = split_into_limbs(n_int);
        // add the append bit
        if end - start == 16 {
            n[4] |= 1 << 24 // when the block is full, the 128th bit is at pos 24 of the last limb
        } else {
            let l = (end - start) * 8;
            let limb = l / 26;
            n[limb] |= 1 << (l % 26); // when the block is not full, we need to find the bit after the last byte of n
        }
        a = add_limbs(a, n);
        a = multiply_mod_p_limbs(a, r);
    }
    // a can still be larger than p
    // so we do a compare-and-subtract against p
    a = fully_reduce(a);
    let tag = limbs_to_integer(a).wrapping_add(s);
    u128::to_le_bytes(tag)
}

// splits into 26 bit limbs carried in u32's
fn split_into_limbs(n: u128) -> [u32; 5] {
    let mut limbs = [0u32; 5];
    for i in 0..5 {
        let limb = (n & (0x03ffffff << (i * 26))) >> (i * 26); // extract 26 bit limbs from the 128 bit number
        limbs[i] = limb.try_into().unwrap();
    }
    limbs
}

fn add_limbs(mut a: [u32; 5], b: [u32; 5]) -> [u32; 5] {
    // since we could have > 2^26 bits
    // after adding to the accumulator,
    // we need to handle the carry bit.
    let mut carry = 0u32;
    for i in 0..5 {
        a[i] += b[i];
        a[i] += carry;
        carry = a[i] >> 26; // essentiall either 1 or 0
        a[i] &= (1 << 26) - 1 // mask off the 27th bit
    }
    // need to check if we still have a carry from the last iteration of the loop above
    a[0] += 5 * carry;
    carry = a[0] >> 26;
    a[0] &= (1 << 26) - 1;
    a[1] += carry;
    a
}

// voodoo witchcraft that I don't fully understand
// the portion of the spec that is [a = (r * a) % p]
fn multiply_mod_p_limbs(a: [u32; 5], r: [u32; 5]) -> [u32; 5] {
    let mut d = [0u64; 9];
    for i in 0..5 {
        for j in 0..5 {
            d[i + j] += u64::from(a[i]) * u64::from(r[j]);
        }
    }
    // fold positions 5 to 9 back into 0 to 4 each scaled by 5
    for k in 5..9 {
        d[k - 5] += 5 * d[k];
        d[k] = 0;
    }
    // carry-propogate back into 26-bit limbs
    let mut carry = 0;
    for i in 0..5 {
        d[i] += carry;
        carry = d[i] >> 26;
        d[i] &= (1 << 26) - 1;
    }
    // the carry falling off the top position 5 again is one more
    // multiple of b^5 ≡ 5, so fold it once more.
    d[0] += 5 * carry;
    carry = d[0] >> 26;
    d[0] &= (1 << 26) - 1;
    d[1] += carry;

    // we have already trimmed all d limbs to < 2^26 and can safely cast to u32
    let mut res = [0u32; 5];
    for i in 0..5 {
        res[i] = u32::try_from(d[i]).unwrap();
    }
    res
}

// The idea: a coming out of the loop is guaranteed < 2p, not necessarily < p.
// So we compute a - p with borrow propagation, and only keep that result if the subtraction didn't need to "borrow past the top"
// I.e., only if a >= p. Otherwise a was already the answer.
fn fully_reduce(mut a: [u32; 5]) -> [u32; 5] {
    let p: [u32; 5] = [
        (1 << 26) - 5,
        (1 << 26) - 1,
        (1 << 26) - 1,
        (1 << 26) - 1,
        (1 << 26) - 1,
    ];

    // The trick is doing the per-limb subtraction in i64 so we can check diff < 0 directly.
    // If a limb would go negative, we borrow 2^26 from the next position and remember to subtract 1 more from the next limb.
    // If we make it all the way through without ever needing that final outstanding borrow, that means a was >= p the whole way,
    // so the subtracted result is the right one; if we did end up needing a borrow past the top, it means a < p all along, and a itself is already correct.
    let mut trial = [0u32; 5];
    let mut borrow: i64 = 0;
    for i in 0..5 {
        let diff = a[i] as i64 - p[i] as i64 - borrow;
        if diff < 0 {
            trial[i] = (diff + (1 << 26)) as u32;
            borrow = 1;
        } else {
            trial[i] = diff as u32;
            borrow = 0;
        }
    }

    if borrow == 0 {
        trial // a >= p, so a - p is the canonical result
    } else {
        a // a < p already, nothing to subtract
    }
}

fn limbs_to_integer(limbs: [u32; 5]) -> u128 {
    let mut n = 0u128;
    for i in 0..5 {
        n |= u128::from(limbs[i] & ((1 << 26) - 1)) << (i * 26); // mask the 26 bits of the limb and then shift them based on their limb index
    }
    n
}

fn pad_16(data: &[u8]) -> Vec<u8> {
    if data.len() % 16 == 0 {
        return data.to_vec();
    }
    let len = 16 - (data.len() % 16);
    let mut padding = vec![0u8; len];
    let mut data_vec = data.to_vec();
    data_vec.append(&mut padding);
    data_vec
}

/// Test vectors are provided in the RFC linked above.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha_quarter_round_test_vector() {
        let (a, b, c, d) = chacha_quarter_round(0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567);

        assert_eq!(
            (a, b, c, d),
            (0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb)
        )
    }

    #[test]
    fn chacha20_block_function_test_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter = 1;

        let block = chacha20_block(&key, &nonce, counter);

        assert_eq!(
            block,
            [
                0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
                0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
                0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
                0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
                0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
            ]
        )
    }

    #[test]
    fn chacha20_encrypt_test_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let counter = 1;

        let msg = chacha20_encrypt(&key, &nonce, plaintext, counter).unwrap();

        assert_eq!(
            msg,
            [
                0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d,
                0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc,
                0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59,
                0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
                0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
                0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d,
                0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9,
                0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
                0x87, 0x4d,
            ]
            .to_vec()
        );
    }

    #[test]
    fn poly1305_mac_test_vector() {
        let key = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";

        let tag = poly1305_mac(&key, msg);

        assert_eq!(
            tag,
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9,
            ]
        );
    }

    #[test]
    fn poly1305_key_gen_test_vector() {
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ];

        let output = poly1305_key_gen(&key, &nonce);

        assert_eq!(
            output,
            [
                0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc, 0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2,
                0x94, 0x71, 0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5, 0x08, 0xdb, 0xb8, 0xe2,
                0xfd, 0xd1, 0xa6, 0x46,
            ]
        );
    }

    #[test]
    fn chacha20_aead_encrypt_decrypt_test_vector() {
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let key = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];

        let (ciphertext, tag) = chacha20_aead_encrypt(&key, &nonce, &aad, plaintext).unwrap();

        assert_eq!(
            ciphertext,
            [
                0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
                0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
                0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
                0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
                0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
                0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
                0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
                0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
                0x61, 0x16,
            ]
        );
        assert_eq!(
            tag,
            [
                0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
                0x06, 0x91,
            ]
        );

        let decrypted_plaintext =
            chacha20_aead_decrypt(&key, &nonce, &aad, &ciphertext, &tag).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
    }
}
