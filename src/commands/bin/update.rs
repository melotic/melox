use crate::{
    app_error::AppError,
    models::{AppState, CreateBinRequest, CreateBinResponse},
};
use axum::{
    debug_handler,
    extract::{Query, State},
    Json,
};
use std::sync::Arc;
use tracing::info;

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
