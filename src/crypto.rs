use anyhow::{Error, bail};

pub(crate) mod aead;
pub(crate) mod ecdsa;
pub(crate) mod hkdf;
pub(crate) mod hmac;
pub(crate) mod sha256;
pub(crate) mod x25519;

pub(crate) fn hkdf_expand_label(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, Error> {
    if label.len() > 255 - 7 {
        bail!("label length too long: {}", label.len())
    }
    if context.len() > 255 {
        bail!("context length too long: {}", context.len())
    }

    // serialze hkdf label as:
    // 2 byte provided length
    // 1 byte label len
    // bytes of label prefixed with "tls13 " (6 fixed bytes)
    // 1 byte context len
    // bytes of context
    let mut hkdf_label = [0u8; 2 + 1 + 255 + 1 + 255];
    hkdf_label[0..2].copy_from_slice(&(length as u16).to_be_bytes());
    hkdf_label[2] = (6 + label.len()) as u8;
    hkdf_label[3..9].copy_from_slice(b"tls13 ");
    let mut pos = 9;
    hkdf_label[pos..pos + label.len()].copy_from_slice(label);
    pos += label.len();
    hkdf_label[pos] = context.len() as u8;
    pos += 1;
    hkdf_label[pos..pos + context.len()].copy_from_slice(context);
    pos += context.len();

    hkdf::expand(secret, &hkdf_label[0..pos], length)
}
