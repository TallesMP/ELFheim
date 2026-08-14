//! On-binary layout of the data block injected into a protected executable.
//!
//! Layout (little-endian):
//!   magic        [u8; 8]  = b"ELFHDATA"
//!   version      u16
//!   pubkey_len   u32
//!   pubkey       [u8; pubkey_len]    developer public key, SPKI DER
//!   license_len  u32
//!   license      [u8; license_len]   license token, Base64 ASCII

const MAGIC: [u8; 8] = *b"ELFHDATA";
const VERSION: u16 = 1;

pub struct Payload {
    pub public_key: Vec<u8>,
    pub license: Vec<u8>,
}

impl Payload {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            MAGIC.len() + 2 + 4 + self.public_key.len() + 4 + self.license.len(),
        );
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&(self.public_key.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&(self.license.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.license);
        buf
    }
}
