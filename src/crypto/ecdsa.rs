/// Reference: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
use anyhow::{Error, bail};

use crate::crypto::sha256::Sha256;

type U256 = [u64; 4]; // little-endian limbs, base 2^64
type Wide = [u64; 8]; // a 512-bit double-width product, same convention

// None = the point at infinity (group identity); Some((x, y)) = an affine point
type Point = Option<(U256, U256)>;

const ZERO: U256 = [0, 0, 0, 0];
const ONE: U256 = [1, 0, 0, 0];
const TWO: U256 = [2, 0, 0, 0];
const THREE: U256 = [3, 0, 0, 0];

// NIST P-256 (secp256r1) domain parameters — SEC2 §2.7 / FIPS 186-4 Appendix D.1.2.3
const P: U256 = [
    0xffffffffffffffff,
    0x00000000ffffffff,
    0x0000000000000000,
    0xffffffff00000001,
];
// a = -3 mod p, precomputed once as a named constant
const A: U256 = [
    0xfffffffffffffffc,
    0x00000000ffffffff,
    0x0000000000000000,
    0xffffffff00000001,
];

#[allow(dead_code)]
const B: U256 = [
    0x3bce3c3e27d2604b,
    0x651d06b0cc53b0f6,
    0xb3ebbd55769886bc,
    0x5ac635d8aa3a93e7,
];
const GX: U256 = [
    0xf4a13945d898c296,
    0x77037d812deb33a0,
    0xf8bce6e563a440f2,
    0x6b17d1f2e12c4247,
];
const GY: U256 = [
    0xcbb6406837bf51f5,
    0x2bce33576b315ece,
    0x8ee7eb4a7c0f9e16,
    0x4fe342e2fe1a7f9b,
];
const N: U256 = [
    0xf3b9cac2fc632551,
    0xbce6faada7179e84,
    0xffffffffffffffff,
    0xffffffff00000000,
];

pub(crate) fn ecdsa_verify_p256(
    public_key: [u8; 65],
    message: &[u8],
    signature_der: &[u8],
) -> bool {
    let q = match parse_public_key(public_key) {
        Ok(q) => q,
        Err(_) => return false,
    };
    let (r, s) = match parse_der_signature(signature_der) {
        Ok(rs) => rs,
        Err(_) => return false,
    };
    // r, s must both be in [1, n-1]
    if r == ZERO || !u256_lt(r, N) || s == ZERO || !u256_lt(s, N) {
        return false;
    }

    let e = u256_from_be_bytes(Sha256::hash(message));
    let w = mod_inv(s, N); // inverts mod the curve ORDER n, not the field prime p
    let u1 = mod_mul(e, w, N);
    let u2 = mod_mul(r, w, N);

    let r_point = point_add(scalar_mult(u1, Some((GX, GY))), scalar_mult(u2, q));
    let Some((rx, _)) = r_point else {
        return false; // point at infinity
    };

    // rx is already < p, but p != n, so reducing it mod n is a real step, not a no-op
    let v = mod_reduce([rx[0], rx[1], rx[2], rx[3], 0, 0, 0, 0], N);
    v == r
}

// ---- Point arithmetic (P-256, short Weierstrass y^2 = x^3 - 3x + b) ----

fn fe_add(a: U256, b: U256) -> U256 {
    mod_add(a, b, P)
}

fn fe_sub(a: U256, b: U256) -> U256 {
    mod_sub(a, b, P)
}

fn fe_mul(a: U256, b: U256) -> U256 {
    mod_mul(a, b, P)
}

fn fe_inv(a: U256) -> U256 {
    mod_inv(a, P)
}

fn point_add(p: Point, q: Point) -> Point {
    match (p, q) {
        (None, _) => q, // infinity + anything = that thing (group identity)
        (_, None) => p,
        (Some((x1, y1)), Some((x2, y2))) => {
            if x1 == x2 && y1 == fe_sub(ZERO, y2) {
                None // same x, inverse y's -> Q = -P, so P + (-P) = infinity
            } else if x1 == x2 && y1 == y2 {
                point_double(p) // generic formula below divides by zero when x1 == x2
            } else {
                let lambda = fe_mul(fe_sub(y2, y1), fe_inv(fe_sub(x2, x1)));
                let x3 = fe_sub(fe_sub(fe_mul(lambda, lambda), x1), x2);
                let y3 = fe_sub(fe_mul(lambda, fe_sub(x1, x3)), y1);
                Some((x3, y3))
            }
        }
    }
}

fn point_double(p: Point) -> Point {
    match p {
        None => None,
        Some((x1, y1)) => {
            if y1 == ZERO {
                None // a point with y=0 is its own inverse; doubling it gives infinity
            } else {
                // lambda = (3*x1^2 + a) / (2*y1)
                let numerator = fe_add(fe_mul(THREE, fe_mul(x1, x1)), A);
                let lambda = fe_mul(numerator, fe_inv(fe_mul(TWO, y1)));
                let x3 = fe_sub(fe_mul(lambda, lambda), fe_mul(TWO, x1));
                let y3 = fe_sub(fe_mul(lambda, fe_sub(x1, x3)), y1);
                Some((x3, y3))
            }
        }
    }
}

// plain double-and-add, not constant-time: fine here, since verification's scalar
// multiplications (u1*G, u2*Q) never involve a secret value
fn scalar_mult(k: U256, p: Point) -> Point {
    let mut result: Point = None;
    for bit in (0..256).rev() {
        result = point_double(result);
        if u256_bit(k, bit) == 1 {
            result = point_add(result, p);
        }
    }
    result
}

// ---- Generic modular arithmetic, parameterized by the modulus (shared between p and n) ----

fn mod_add(a: U256, b: U256, modulus: U256) -> U256 {
    let (sum, carry) = u256_add(a, b);
    if carry || !u256_lt(sum, modulus) {
        u256_sub(sum, modulus).0
    } else {
        sum
    }
}

fn mod_sub(a: U256, b: U256, modulus: U256) -> U256 {
    let (diff, borrowed) = u256_sub(a, b);
    if borrowed {
        u256_add(diff, modulus).0
    } else {
        diff
    }
}

fn mod_mul(a: U256, b: U256, modulus: U256) -> U256 {
    mod_reduce(u256_mul_wide(a, b), modulus)
}

fn mod_pow(base: U256, exponent: U256, modulus: U256) -> U256 {
    // square-and-multiply, MSB down to LSB
    let mut result: U256 = ONE;
    for bit in (0..256).rev() {
        result = mod_mul(result, result, modulus);
        if u256_bit(exponent, bit) == 1 {
            result = mod_mul(result, base, modulus);
        }
    }
    result
}

// valid because both p and n are prime
fn mod_inv(a: U256, modulus: U256) -> U256 {
    mod_pow(a, u256_sub(modulus, TWO).0, modulus)
}

// bit-serial binary long division: brings a double-width value back down to a
// canonical remainder < modulus, one bit at a time, most significant bit first
fn mod_reduce(wide: Wide, modulus: U256) -> U256 {
    let mut remainder: U256 = ZERO;
    for bit_idx in (0..512).rev() {
        // remainder's own top bit, about to be shifted away — the conceptual "bit 256"
        // that doesn't fit back into remainder's 4 limbs
        let carried_out = (remainder[3] >> 63) & 1;
        remainder = shift_left_1(remainder);
        remainder[0] |= wide_bit(wide, bit_idx);

        if carried_out == 1 || !u256_lt(remainder, modulus) {
            remainder = u256_sub(remainder, modulus).0;
        }
    }
    remainder
}

// ---- U256 primitives: no modulus involved, just fixed-width carry/borrow arithmetic ----

fn u256_add(a: U256, b: U256) -> (U256, bool) {
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (sum1, overflow1) = a[i].overflowing_add(b[i]);
        let (sum2, overflow2) = sum1.overflowing_add(carry);
        result[i] = sum2;
        carry = u64::from(overflow1) + u64::from(overflow2);
    }
    (result, carry != 0)
}

fn u256_sub(a: U256, b: U256) -> (U256, bool) {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (diff1, underflow1) = a[i].overflowing_sub(b[i]);
        let (diff2, underflow2) = diff1.overflowing_sub(borrow);
        result[i] = diff2;
        borrow = u64::from(underflow1) + u64::from(underflow2);
    }
    (result, borrow != 0)
}

fn u256_lt(a: U256, b: U256) -> bool {
    u256_sub(a, b).1
}

fn u256_mul_wide(a: U256, b: U256) -> Wide {
    // schoolbook 4x4, one row of b at a time with the carry propagated immediately —
    // unlike X25519's ~51-bit limbs, these are full 64-bit limbs, so a single column
    // can't hold more than one raw product before it risks overflowing even a u128
    // (two (2^64-1)^2 products alone exceed 2^128); carrying within each row first
    // keeps every running sum at or under 2^128-1.
    let mut result = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let product = u128::from(a[i]) * u128::from(b[j]) + u128::from(result[i + j]) + carry;
            result[i + j] = product as u64;
            carry = product >> 64;
        }
        result[i + 4] = carry as u64;
    }
    result
}

fn shift_left_1(x: U256) -> U256 {
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        result[i] = (x[i] << 1) | carry;
        carry = x[i] >> 63;
    }
    result
}

fn u256_bit(x: U256, bit: usize) -> u64 {
    (x[bit / 64] >> (bit % 64)) & 1
}

fn wide_bit(x: Wide, bit: usize) -> u64 {
    (x[bit / 64] >> (bit % 64)) & 1
}

fn u256_from_be_bytes(bytes: [u8; 32]) -> U256 {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        // limb 0 = least-significant 8 bytes = the LAST 8 bytes of a big-endian array
        let chunk: [u8; 8] = bytes[(24 - i * 8)..(32 - i * 8)].try_into().unwrap();
        limbs[i] = u64::from_be_bytes(chunk);
    }
    limbs
}

#[allow(dead_code)]
fn u256_to_be_bytes(x: U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        bytes[(24 - i * 8)..(32 - i * 8)].copy_from_slice(&x[i].to_be_bytes());
    }
    bytes
}

// ---- Parsing ----

fn parse_public_key(bytes: [u8; 65]) -> Result<Point, Error> {
    if bytes[0] != 0x04 {
        bail!("public key: unsupported point encoding");
    }
    let x: [u8; 32] = bytes[1..33].try_into()?;
    let y: [u8; 32] = bytes[33..65].try_into()?;
    Ok(Some((u256_from_be_bytes(x), u256_from_be_bytes(y))))
}

fn parse_der_signature(der: &[u8]) -> Result<(U256, U256), Error> {
    if der.is_empty() || der[0] != 0x30 {
        bail!("der signature: expected SEQUENCE tag");
    }
    let (_seq_len, mut pos) = parse_der_length(der, 1)?;

    if pos >= der.len() || der[pos] != 0x02 {
        bail!("der signature: expected INTEGER tag for r");
    }
    let (r_len, r_start) = parse_der_length(der, pos + 1)?;
    if r_start + r_len > der.len() {
        bail!("der signature: r integer out of bounds");
    }
    let r = der_integer_to_u256(&der[r_start..r_start + r_len])?;
    pos = r_start + r_len;

    if pos >= der.len() || der[pos] != 0x02 {
        bail!("der signature: expected INTEGER tag for s");
    }
    let (s_len, s_start) = parse_der_length(der, pos + 1)?;
    if s_start + s_len > der.len() {
        bail!("der signature: s integer out of bounds");
    }
    let s = der_integer_to_u256(&der[s_start..s_start + s_len])?;

    Ok((r, s))
}

// DER length, short or (minimally) long form; returns (length, position just past the length bytes)
fn parse_der_length(der: &[u8], pos: usize) -> Result<(usize, usize), Error> {
    if pos >= der.len() {
        bail!("der length: out of bounds");
    }
    let first = der[pos];
    if first & 0x80 == 0 {
        Ok((usize::from(first), pos + 1))
    } else {
        let num_bytes = usize::from(first & 0x7f);
        if num_bytes == 0 || num_bytes > 2 || pos + 1 + num_bytes > der.len() {
            bail!("der length: unsupported long-form encoding");
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | usize::from(der[pos + 1 + i]);
        }
        Ok((len, pos + 1 + num_bytes))
    }
}

// DER INTEGERs are signed, two's-complement, minimal-length encodings: since r and s are
// always positive here, this only ever means a single leading 0x00 byte, present exactly
// when the integer's top bit would otherwise look like a sign bit.
fn der_integer_to_u256(bytes: &[u8]) -> Result<U256, Error> {
    let trimmed = if bytes.len() == 33 && bytes[0] == 0x00 {
        &bytes[1..]
    } else {
        bytes
    };
    if trimmed.is_empty() || trimmed.len() > 32 {
        bail!("der integer: unexpected length");
    }
    let mut padded = [0u8; 32];
    padded[(32 - trimmed.len())..].copy_from_slice(trimmed);
    Ok(u256_from_be_bytes(padded))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u256_be_bytes_roundtrip() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        assert_eq!(u256_to_be_bytes(u256_from_be_bytes(bytes)), bytes);
    }

    #[test]
    fn mod_add_sub_small_values() {
        // mod_add/mod_sub expect operands already reduced (< modulus)
        let a = [5, 0, 0, 0];
        let b = [4, 0, 0, 0];
        let m = [7, 0, 0, 0];

        assert_eq!(mod_add(a, b, m), [2, 0, 0, 0]); // (5+4) mod 7 == 2
        assert_eq!(mod_sub(a, b, m), [1, 0, 0, 0]); // (5-4) mod 7 == 1
        assert_eq!(mod_sub(b, a, m), [6, 0, 0, 0]); // (4-5) mod 7 == 6
    }

    #[test]
    fn mod_mul_small_values() {
        assert_eq!(
            mod_mul([2, 0, 0, 0], [3, 0, 0, 0], [7, 0, 0, 0]),
            [6, 0, 0, 0]
        );
    }

    #[test]
    fn mod_pow_small_values() {
        // 3^5 = 243, 243 mod 13 = 9
        assert_eq!(
            mod_pow([3, 0, 0, 0], [5, 0, 0, 0], [13, 0, 0, 0]),
            [9, 0, 0, 0]
        );
    }

    #[test]
    fn mod_inv_small_values() {
        // 2 * 4 = 8 == 1 mod 7
        assert_eq!(mod_inv([2, 0, 0, 0], [7, 0, 0, 0]), [4, 0, 0, 0]);
    }

    #[test]
    fn base_point_is_on_curve() {
        // y^2 == x^3 - 3x + b (mod p)
        let lhs = fe_mul(GY, GY);
        let rhs = fe_add(fe_sub(fe_mul(fe_mul(GX, GX), GX), fe_mul(THREE, GX)), B);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn point_add_handles_infinity() {
        let g = Some((GX, GY));
        assert_eq!(point_add(None, g), g);
        assert_eq!(point_add(g, None), g);
    }

    #[test]
    fn point_add_dispatches_to_double_and_handles_inverses() {
        let g = Some((GX, GY));
        assert_eq!(point_add(g, g), point_double(g));

        let neg_g = Some((GX, fe_sub(ZERO, GY)));
        assert_eq!(point_add(g, neg_g), None);
    }

    #[test]
    fn scalar_mult_matches_repeated_doubling() {
        let g = Some((GX, GY));
        let two_g = point_double(g);
        assert_eq!(scalar_mult([2, 0, 0, 0], g), two_g);

        let four_g = point_double(two_g);
        assert_eq!(scalar_mult([4, 0, 0, 0], g), four_g);
    }

    // Valid signature, public key, and message independently generated and self-verified
    // via Node's `crypto` module (OpenSSL under the hood) — see specs/crypto/06-ecdsa-p256.md §7.
    #[test]
    fn ecdsa_verify_p256_accepts_valid_signature() {
        let public_key: [u8; 65] = hex("04a3d295e2721d3c27330d7f77a4169c358a376cb4e02587a360e41dcc2376b26636bc1b2d6d157a535b94ac0ffa51d1ba4025a10775fae9d5c44005cb3ded64f7").try_into().unwrap();
        let message = b"smolcurl ecdsa test vector";
        let signature_der = hex(
            "30450220040b9a4e1140703d7262300ea28816bb761f7430446f76080ebdbd7064efa25d022100945df143949ca73f77b10d56eb15fd4edd48793232db5c46a713dd2c20106275",
        );

        assert!(ecdsa_verify_p256(public_key, message, &signature_der));
    }

    #[test]
    fn ecdsa_verify_p256_rejects_tampered_signature() {
        let public_key: [u8; 65] = hex("04a3d295e2721d3c27330d7f77a4169c358a376cb4e02587a360e41dcc2376b26636bc1b2d6d157a535b94ac0ffa51d1ba4025a10775fae9d5c44005cb3ded64f7").try_into().unwrap();
        let message = b"smolcurl ecdsa test vector";
        // last byte of s flipped relative to the valid vector above
        let signature_der = hex(
            "30450220040b9a4e1140703d7262300ea28816bb761f7430446f76080ebdbd7064efa25d022100945df143949ca73f77b10d56eb15fd4edd48793232db5c46a713dd2c20106274",
        );

        assert!(!ecdsa_verify_p256(public_key, message, &signature_der));
    }

    #[test]
    fn ecdsa_verify_p256_rejects_wrong_message() {
        let public_key: [u8; 65] = hex("04a3d295e2721d3c27330d7f77a4169c358a376cb4e02587a360e41dcc2376b26636bc1b2d6d157a535b94ac0ffa51d1ba4025a10775fae9d5c44005cb3ded64f7").try_into().unwrap();
        let message = b"not the signed message";
        let signature_der = hex(
            "30450220040b9a4e1140703d7262300ea28816bb761f7430446f76080ebdbd7064efa25d022100945df143949ca73f77b10d56eb15fd4edd48793232db5c46a713dd2c20106275",
        );

        assert!(!ecdsa_verify_p256(public_key, message, &signature_der));
    }

    // Exercises the DER "leading 0x00 padding byte" path: r is a 33-byte INTEGER here.
    #[test]
    fn ecdsa_verify_p256_accepts_signature_with_padded_r() {
        let public_key: [u8; 65] = hex("04b1ea8fc70fbeddcdd5485be3421ae8c3f23c185734edd83b5b01ae610746ee755969ca711bf00102263747ec404e24e3a9216472ff03e7947ac7a582c73ba223").try_into().unwrap();
        let message = b"smolcurl padded-der test vector";
        let signature_der = hex(
            "3045022100c321b21c521a5c7c638411cbded17efec027e0f60b7bdaa6400b71e1348aaafe022041628043a6651f708e3ab81dab88ec0651c6a01a35e66164a22b859f424c65bd",
        );

        assert!(ecdsa_verify_p256(public_key, message, &signature_der));
    }

    #[test]
    fn ecdsa_verify_p256_rejects_malformed_der() {
        let public_key: [u8; 65] = hex("04a3d295e2721d3c27330d7f77a4169c358a376cb4e02587a360e41dcc2376b26636bc1b2d6d157a535b94ac0ffa51d1ba4025a10775fae9d5c44005cb3ded64f7").try_into().unwrap();
        let message = b"smolcurl ecdsa test vector";

        assert!(!ecdsa_verify_p256(public_key, message, &[]));
        assert!(!ecdsa_verify_p256(
            public_key,
            message,
            &[0x30, 0x02, 0x02, 0x01]
        ));
    }

    #[test]
    fn ecdsa_verify_p256_rejects_bad_public_key_prefix() {
        let mut public_key = [0u8; 65];
        public_key[0] = 0x02; // compressed-point prefix, unsupported by this project's scope
        let message = b"smolcurl ecdsa test vector";
        let signature_der = hex(
            "30450220040b9a4e1140703d7262300ea28816bb761f7430446f76080ebdbd7064efa25d022100945df143949ca73f77b10d56eb15fd4edd48793232db5c46a713dd2c20106275",
        );

        assert!(!ecdsa_verify_p256(public_key, message, &signature_der));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
