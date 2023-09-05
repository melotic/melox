use crate::{app_error::AppError, models::AppState};
use axum::extract::{Path, State};
use std::sync::Arc;
use tracing::info;

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
