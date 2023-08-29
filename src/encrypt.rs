use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, OsRng},
    AeadCore, Aes128Gcm, KeyInit, KeySizeUser,
};
use axum::http::StatusCode;

// don't hardcode Aes128Gcm
type GcmSize = Aes128Gcm;

pub trait BinEncrypter {
    fn generate_key_and_encrypt(
        &self,
        content: &str,
    ) -> Result<
        (
            GenericArray<u8, <GcmSize as KeySizeUser>::KeySize>,
            GenericArray<u8, <GcmSize as AeadCore>::NonceSize>,
            Vec<u8>,
        ),
        StatusCode,
    >;

    fn decrypt(
        &self,
        key: GenericArray<u8, <GcmSize as KeySizeUser>::KeySize>,
        nonce: GenericArray<u8, <GcmSize as AeadCore>::NonceSize>,
        ciphertext: &[u8],
    ) -> Result<String, StatusCode>;
}

pub struct Aes128BinEncryption;

impl BinEncrypter for Aes128BinEncryption {
    fn generate_key_and_encrypt(
        &self,
        content: &str,
    ) -> Result<
        (
            GenericArray<u8, <GcmSize as KeySizeUser>::KeySize>,
            GenericArray<u8, <GcmSize as AeadCore>::NonceSize>,
            Vec<u8>,
        ),
        StatusCode,
    > {
        let key = GcmSize::generate_key(OsRng);
        let cipher = GcmSize::new(&key);
        let nonce = GcmSize::generate_nonce(OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, content.as_bytes())
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        Ok((key, nonce, ciphertext))
    }

    fn decrypt(
        &self,
        key: GenericArray<u8, <GcmSize as KeySizeUser>::KeySize>,
        nonce: GenericArray<u8, <GcmSize as AeadCore>::NonceSize>,
        ciphertext: &[u8],
    ) -> Result<String, StatusCode> {
        let cipher = GcmSize::new(&key);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        Ok(String::from_utf8(plaintext).unwrap())
    }
}
