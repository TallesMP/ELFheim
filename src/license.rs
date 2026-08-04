use base64::{Engine, engine::general_purpose::STANDARD};
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use sha2::Sha256;

const MAGIC: [u8; 4] = *b"ELFH";
const FORMAT_VERSION: u16 = 1;

pub struct License {
    pub user_id: u64,
    pub product_id: u32,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl License {
    fn metadata(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(34);
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        buf.extend_from_slice(&self.user_id.to_le_bytes());
        buf.extend_from_slice(&self.product_id.to_le_bytes());
        buf.extend_from_slice(&self.issued_at.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        buf
    }

    pub fn sign(&self, private_key: RsaPrivateKey) -> Result<String, rsa::signature::Error> {
        let metadata = self.metadata();
        let signing_key = SigningKey::<Sha256>::new(private_key);
        let signature = signing_key.try_sign(&metadata)?;
        let mut token = metadata;
        token.extend_from_slice(&signature.to_bytes());
        Ok(STANDARD.encode(token))
    }
}
