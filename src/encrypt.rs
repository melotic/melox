use crate::app_error::AppError;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, OsRng},
    AeadCore, Aes128Gcm, KeyInit, KeySizeUser,
};
use anyhow::{anyhow, Context};

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
        AppError,
    >;

    fn decrypt(
        &self,
        key: GenericArray<u8, <GcmSize as KeySizeUser>::KeySize>,
        nonce: GenericArray<u8, <GcmSize as AeadCore>::NonceSize>,
        ciphertext: &[u8],
    ) -> Result<String, AppError>;
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
        AppError,
    > {
        let key = GcmSize::generate_key(OsRng);
        let cipher = GcmSize::new(&key);
        let nonce = GcmSize::generate_nonce(OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, content.as_bytes())
            .map_err(|e| anyhow!(e))
            .with_context(|| "encrypting user content")?;

        Ok((key, nonce, ciphertext))
    }

    fn decrypt(
        &self,
        key: GenericArray<u8, <GcmSize as KeySizeUser>::KeySize>,
        nonce: GenericArray<u8, <GcmSize as AeadCore>::NonceSize>,
        ciphertext: &[u8],
    ) -> Result<String, AppError> {
        let cipher = GcmSize::new(&key);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!(e))
            .with_context(|| "decrypting user content")?;

        Ok(String::from_utf8(plaintext).map_err(|e| anyhow!(e))?)
    }
}
