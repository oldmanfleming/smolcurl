use anyhow::{Context, Error};

// Trait for providing common functions for converting to/from fixed size byte slices
pub(crate) trait ByteLen: Sized {
    type Bytes: AsRef<[u8]>;
    fn from_len(n: usize) -> Result<Self, Error>;
    fn into_be_bytes(self) -> Self::Bytes;
    fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error>;
    fn byte_len() -> usize;
}

impl ByteLen for u8 {
    type Bytes = [u8; 1];
    fn from_len(n: usize) -> Result<Self, Error> {
        n.try_into().context("length too large for u8")
    }

    fn into_be_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(u8::from_be_bytes(bytes.try_into()?))
    }

    fn byte_len() -> usize {
        1
    }
}

impl ByteLen for u16 {
    type Bytes = [u8; 2];
    fn from_len(n: usize) -> Result<Self, Error> {
        n.try_into().context("length too large for u16")
    }

    fn into_be_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(u16::from_be_bytes(bytes.try_into()?))
    }

    fn byte_len() -> usize {
        2
    }
}

impl ByteLen for u32 {
    type Bytes = [u8; 4];
    fn from_len(n: usize) -> Result<Self, Error> {
        n.try_into().context("length too large for u32")
    }

    fn into_be_bytes(self) -> Self::Bytes {
        self.to_be_bytes()
    }

    fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(u32::from_be_bytes(bytes.try_into()?))
    }

    fn byte_len() -> usize {
        4
    }
}
