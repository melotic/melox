#[cfg(test)]
use mockall::{automock, mock, predicate::*};

use crate::app_error::AppError;
use aes_gcm::{
    aead::{
        consts::{U12, U16},
        generic_array::GenericArray,
        Aead, OsRng,
    },
    AeadCore, Aes128Gcm, KeyInit,
};
use anyhow::{anyhow, Context};

#[cfg_attr(test, automock)]
pub trait BinEncrypter {
    fn generate_key_and_encrypt(
        &self,
        content: &str,
    ) -> Result<(GenericArray<u8, U16>, GenericArray<u8, U12>, Vec<u8>), AppError>;

    fn decrypt(
        &self,
        key: GenericArray<u8, U16>,
        nonce: GenericArray<u8, U12>,
        ciphertext: &[u8],
    ) -> Result<String, AppError>;
}

pub struct Aes128BinEncryption;

impl BinEncrypter for Aes128BinEncryption {
    fn generate_key_and_encrypt(
        &self,
        content: &str,
    ) -> Result<(GenericArray<u8, U16>, GenericArray<u8, U12>, Vec<u8>), AppError> {
        let key = Aes128Gcm::generate_key(OsRng);
        let cipher = Aes128Gcm::new(&key);
        let nonce = Aes128Gcm::generate_nonce(OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, content.as_bytes())
            .map_err(|e| anyhow!(e))
            .with_context(|| "encrypting user content")?;

        Ok((key, nonce, ciphertext))
    }

    fn decrypt(
        &self,
        key: GenericArray<u8, U16>,
        nonce: GenericArray<u8, U12>,
        ciphertext: &[u8],
    ) -> Result<String, AppError> {
        let cipher = Aes128Gcm::new(&key);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| anyhow!(e))
            .with_context(|| "decrypting user content")?;

        Ok(String::from_utf8(plaintext).map_err(|e| anyhow!(e))?)
    }
}
