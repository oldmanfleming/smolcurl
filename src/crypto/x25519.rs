/// Reference: https://www.rfc-editor.org/info/rfc7748/

// limb i holds a value at a conceptually higher digit position with base 2^51
type Fe = [u64; 5];

const P_LIMBS: [u64; 5] = [
    0x7_ffff_ffff_ffed, // 2^51 - 19
    0x7_ffff_ffff_ffff, // 2^51 - 1
    0x7_ffff_ffff_ffff, // 2^51 - 1
    0x7_ffff_ffff_ffff, // 2^51 - 1
    0x7_ffff_ffff_ffff, // 2^51 - 1
];

pub(crate) fn x25519(k: [u8; 32], u: [u8; 32]) -> [u8; 32] {
    let k = clamp_scalar(k);
    let x1 = decode_u_coordinate(u);
    let mut x2 = fe_one();
    let mut z2: Fe = [0, 0, 0, 0, 0];
    let mut x3 = x1;
    let mut z3 = fe_one();
    let mut swap = 0u8;
    for t in (0..255).rev() {
        let k_t = k[t / 8] >> (t % 8) & 1;
        swap ^= k_t;
        cswap(swap, &mut x2, &mut x3);
        cswap(swap, &mut z2, &mut z3);
        swap = k_t;
        let a = fe_add(x2, z2);
        let aa = fe_sqr(a);
        let b = fe_sub(x2, z2);
        let bb = fe_sqr(b);
        let e = fe_sub(aa, bb);
        let c = fe_add(x3, z3);
        let d = fe_sub(x3, z3);
        let da = fe_mul(d, a);
        let cb = fe_mul(c, b);
        x3 = fe_sqr(fe_add(da, cb));
        z3 = fe_mul(x1, fe_sqr(fe_sub(da, cb)));
        x2 = fe_mul(aa, bb);
        z2 = fe_mul(e, fe_add(aa, fe_mul_scalar(e, 121665)));
    }
    cswap(swap, &mut x2, &mut x3);
    cswap(swap, &mut z2, &mut z3);
    let result = fe_mul(x2, fe_invert(z2));
    encode_u_coordinate(result)
}

fn clamp_scalar(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 0b1111_1000;
    k[31] &= 0b0111_1111;
    k[31] |= 0b0100_0000;
    k
}

fn decode_u_coordinate(mut bytes: [u8; 32]) -> Fe {
    bytes[31] &= 0b0111_1111;
    fe_from_bytes(bytes)
}

fn encode_u_coordinate(u: Fe) -> [u8; 32] {
    fe_to_bytes(fe_reduce(u)) // fe is < 2^255 but not necessarily < p, so we still need to reduce.
}

fn cswap(swap: u8, a: &mut Fe, b: &mut Fe) {
    if swap == 1 {
        for i in 0..5 {
            let tmp = a[i];
            a[i] = b[i];
            b[i] = tmp;
        }
    }
}

// mask out every bit of bytes and insert it into it's equivalent position within limbs
fn fe_from_bytes(bytes: [u8; 32]) -> Fe {
    let mut limbs = [0u64; 5];
    for i in 0..32 {
        let byte = bytes[i];
        for j in 0..8 {
            let bit = (byte & (1 << j)) >> j;
            let global_pos = i * 8 + j;
            // top bits of bytes should already be masked off.
            if global_pos >= 255 {
                continue;
            }
            limbs[global_pos / 51] |= u64::from(bit) << (global_pos % 51);
        }
    }
    limbs
}

// mask out every bit of limbs and insert it into it's equivalent position within bytes
fn fe_to_bytes(limbs: Fe) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..5 {
        let limb = limbs[i];
        for j in 0..51 {
            let bit = ((limb & (1 << j)) >> j) as u8;
            let global_pos = i * 51 + j;
            bytes[global_pos / 8] |= bit << (global_pos % 8);
        }
    }
    bytes
}

fn fe_add(mut a: Fe, b: Fe) -> Fe {
    let mask = (1u64 << 51) - 1;
    let mut carry = 0u64;
    for i in 0..5 {
        a[i] = a[i] + b[i] + carry;
        carry = a[i] >> 51;
        a[i] &= mask;
    }
    a[0] += 19 * carry;
    carry = a[0] >> 51;
    a[0] &= mask;
    a[1] += carry;
    a
}

fn fe_sub(a: Fe, b: Fe) -> Fe {
    let mask = (1u64 << 51) - 1;
    let mut carry = 0u64;
    let mut d = [0u64; 5];
    for i in 0..5 {
        // 2*p_limbs[i] is always large enough that a[i] + 2*p_limbs[i] - b[i]
        // can't go negative, since a[i], b[i] < 2^51 < 2*p_limbs[i].
        // Adding 2*p doesn't change the value mod p (2p ≡ 0 mod p), so this
        // is still a legal representation of (a - b) mod p.
        d[i] = a[i] + 2 * P_LIMBS[i] - b[i] + carry;
        carry = d[i] >> 51;
        d[i] &= mask;
    }
    d[0] += 19 * carry; // same final fold as fe_add
    carry = d[0] >> 51;
    d[0] &= mask;
    d[1] += carry;
    d
}

fn fe_mul(a: Fe, b: Fe) -> Fe {
    let mut d = [0u128; 9]; // u128: two ~51-bit limbs multiply to ~102 bits,
    // and up to 5 such products land in one column
    for i in 0..5 {
        for j in 0..5 {
            d[i + j] += u128::from(a[i]) * u128::from(b[j]);
        }
    }

    // columns 5..9 are coefficients of 2^(255), 2^(306), ... — all multiples
    // of 2^255, so fold each by 19 into the column 5 positions lower.
    for k in 5..9 {
        d[k - 5] += 19 * d[k];
        d[k] = 0;
    }

    let mask = (1u128 << 51) - 1;
    let mut carry = 0u128;
    for i in 0..5 {
        d[i] += carry;
        carry = d[i] >> 51;
        d[i] &= mask;
    }

    // carry off the top of d[4] is again a coefficient of 2^255 — fold once more.
    d[0] += 19 * carry;
    carry = d[0] >> 51;
    d[0] &= mask;
    d[1] += carry;

    [
        d[0] as u64,
        d[1] as u64,
        d[2] as u64,
        d[3] as u64,
        d[4] as u64,
    ]
}

fn fe_mul_scalar(a: Fe, b: u32) -> Fe {
    fe_mul(a, fe_from_small_int(b))
}

fn fe_sqr(a: Fe) -> Fe {
    fe_mul(a, a)
}

fn fe_reduce(a: Fe) -> Fe {
    let mut trial = [0u64; 5];
    let mut borrow: i64 = 0;
    for i in 0..5 {
        let diff = a[i] as i64 - P_LIMBS[i] as i64 - borrow;
        if diff < 0 {
            trial[i] = (diff + (1 << 51)) as u64;
            borrow = 1;
        } else {
            trial[i] = diff as u64;
            borrow = 0;
        }
    }

    if borrow == 0 {
        trial // a >= p, so a - p is the canonical result
    } else {
        a // a < p already, nothing to subtract
    }
}

// p - 2, as a 255-bit constant split into high and low limbs
const P_MINUS_2_HIGH: u128 = 0x7fffffffffffffffffffffffffffffff;
const P_MINUS_2_LOW: u128 = 0xffffffffffffffffffffffffffffffeb;

fn fe_invert(a: Fe) -> Fe {
    let mut result = fe_one();
    for bit in (0..255).rev() {
        // MSB (254) down to LSB (0) — 255 iterations
        result = fe_sqr(result);
        let p_minus_2_bit = if bit >= 128 {
            P_MINUS_2_HIGH >> (bit - 128)
        } else {
            P_MINUS_2_LOW >> bit
        };
        if p_minus_2_bit & 1 == 1 {
            result = fe_mul(result, a);
        }
    }
    result
}

fn fe_one() -> Fe {
    [1u64, 0u64, 0u64, 0u64, 0u64]
}

fn fe_from_small_int(n: u32) -> Fe {
    [u64::from(n), 0, 0, 0, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_1() {
        let k = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let u = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];

        let out = x25519(k, u);

        assert_eq!(
            out,
            [
                0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
                0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
                0x77, 0xa2, 0x85, 0x52,
            ]
        );
    }

    #[test]
    fn test_vector_2() {
        let k = [
            0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d,
            0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e,
            0x79, 0x18, 0xba, 0x0d,
        ];
        let u = [
            0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38,
            0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49,
            0xc7, 0x15, 0xa4, 0x93,
        ];

        let out = x25519(k, u);

        assert_eq!(
            out,
            [
                0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8,
                0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64,
                0x7a, 0xac, 0x79, 0x57,
            ]
        );
    }
}
