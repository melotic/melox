use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tracing::error;

#[derive(Debug)]
pub enum AppError {
    InternalServerError(anyhow::Error),
    BinNotFound,
    InvalidEditToken,
}

impl From<anyhow::Error> for AppError {
    fn from(inner: anyhow::Error) -> Self {
        AppError::InternalServerError(inner)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InternalServerError(inner) => {
                error!("Internal server error: {}", inner);
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
            }
            AppError::BinNotFound => (StatusCode::NOT_FOUND, "bin not found"),
            AppError::InvalidEditToken => (StatusCode::BAD_REQUEST, "invalid edit token"),
        };

        let body = Json(json!({ "error": error_message }));

        (status, body).into_response()
    }
}
