use crate::{
    app_error::AppError,
    commands::id_to_b58,
    models::{AppState, CreateBinRequest, CreateBinResponse, DbBin},
};
use axum::{debug_handler, extract::State, Json};
use std::sync::Arc;
use tracing::info;

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
