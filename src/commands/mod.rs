use crate::{
    app_error::AppError,
    models::{CreateBinRequest, CreateBinResponse, DbBin},
    AppState,
};
use aes_gcm::aead::generic_array::GenericArray;
use axum::{
    debug_handler,
    extract::{Path, Query, State},
    Json,
};
use std::sync::Arc;
use tracing::info;

fn id_to_b58(x: u64) -> String {
    bs58::encode(x.to_be_bytes()).into_string()
}

#[debug_handler]
pub async fn create_bin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateBinRequest>,
) -> Result<Json<CreateBinResponse>, AppError> {
    let (key, nonce, ciphertext) = state.encrypter.generate_key_and_encrypt(&req.content)?;

    let id = id_to_b58(rand::random::<u64>());
    let edit_token = id_to_b58(rand::random::<u64>());

    info!(
        "Creating bin {id} - {ct_len}",
        id = id,
        ct_len = ciphertext.len()
    );

    let bin = DbBin {
        id: id.clone(),
        content: ciphertext,
        edit_token: edit_token.clone(),
    };

    state.db_client.create_bin(bin).await?;

    Ok(Json(CreateBinResponse {
        id,
        key: bs58::encode(key).into_string(),
        nonce: bs58::encode(nonce).into_string(),
        edit_token,
    }))
}

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

#[debug_handler]
pub async fn update_bin(
    State(state): State<Arc<AppState>>,
    Query((id, edit_token)): Query<(String, String)>,
    Json(req): Json<CreateBinRequest>,
) -> Result<Json<CreateBinResponse>, AppError> {
    info!("Updating bin {id}", id = id);

    let bin = state.db_client.get_bin(&id).await.unwrap();

    if bin.edit_token != edit_token {
        info!("Invalid edit token {id}", id = id);
        return Err(AppError::InvalidEditToken);
    }

    let (key, nonce, ciphertext) = state
        .encrypter
        .generate_key_and_encrypt(&req.content)
        .unwrap();

    state.db_client.update_bin(&id, ciphertext).await.unwrap();
    info!("Updated bin {id}", id = id);

    Ok(Json(CreateBinResponse {
        id,
        key: bs58::encode(key).into_string(),
        nonce: bs58::encode(nonce).into_string(),
        edit_token,
    }))
}

pub async fn delete_bin(
    State(state): State<Arc<AppState>>,
    Path((id, edit_token)): Path<(String, String)>,
) -> Result<String, AppError> {
    info!("Deleting bin {}", id);

    let bin = state.db_client.get_bin(&id).await.unwrap();

    if bin.edit_token != edit_token {
        info!("Invalid edit token {id}", id = id);
        return Err(AppError::InvalidEditToken);
    }

    state.db_client.delete_bin(&id).await.unwrap();

    Ok("".to_string())
}
