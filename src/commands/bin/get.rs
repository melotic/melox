use crate::models::AppState;
use aes_gcm::aead::generic_array::GenericArray;
use axum::extract::{Path, State};
use std::sync::Arc;
use tracing::info;

pub async fn get_bin(
    State(state): State<Arc<AppState>>,
    Path((id, key, nonce)): Path<(String, String, String)>,
) -> String {
    info!("Getting bin {}", id);

    let bin = state.db_client.get_bin(&id).await.unwrap();

    let key = bs58::decode(key).into_vec().unwrap();
    let nonce = bs58::decode(nonce).into_vec().unwrap();

    let plaintext = state
        .encrypter
        .decrypt(
            *GenericArray::from_slice(&key),
            *GenericArray::from_slice(&nonce),
            &bin.content,
        )
        .unwrap();

    plaintext
}
