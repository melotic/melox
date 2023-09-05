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

#[cfg(test)]
mod tests {
    use super::create_bin;
    use crate::{
        app_error::AppError,
        database::MockDbClient,
        encrypt::MockBinEncrypter,
        models::{AppState, CreateBinRequest, DbBin},
    };
    use aes_gcm::aead::generic_array::GenericArray;
    use axum::{extract::State, Json};
    use mockall::predicate;
    use std::sync::Arc;

    fn create_mocks() -> (MockDbClient, MockBinEncrypter) {
        let mock_db_client = MockDbClient::new();
        let mock_encrypter = MockBinEncrypter::new();

        (mock_db_client, mock_encrypter)
    }

    #[tokio::test]
    async fn create_bin_happy_path() {
        let bin_content = "hello world";
        let (mut mock_db_client, mut mock_encrypter) = create_mocks();

        mock_encrypter
            .expect_generate_key_and_encrypt()
            .with(predicate::eq(bin_content))
            .returning(|_| {
                Ok((
                    *GenericArray::from_slice(&[0; 16]),
                    *GenericArray::from_slice(&[0; 12]),
                    vec![0; 16],
                ))
            });

        mock_db_client
            .expect_create_bin()
            .with(predicate::function(|x: &DbBin| x.content == vec![0; 16]))
            .returning(|_| Ok(()));

        let app_state = AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        };

        let req = CreateBinRequest {
            content: bin_content.to_string(),
        };

        let res = create_bin(State(Arc::new(app_state)), Json(req)).await;

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn create_bin_encrypt_fail() {
        let bin_content = "hello world";
        let (mock_db_client, mut mock_encrypter) = create_mocks();

        mock_encrypter
            .expect_generate_key_and_encrypt()
            .with(predicate::eq(bin_content))
            .returning(|_| Err(anyhow::anyhow!("encrypt error").into()));

        let app_state = AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        };

        let req = CreateBinRequest {
            content: bin_content.to_string(),
        };

        let res = create_bin(State(Arc::new(app_state)), Json(req)).await;

        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), AppError::InternalServerError(_)));
    }

    #[tokio::test]
    async fn create_bin_db_fail() {
        let bin_content = "hello world";
        let (mut mock_db_client, mut mock_encrypter) = create_mocks();

        mock_encrypter
            .expect_generate_key_and_encrypt()
            .with(predicate::eq(bin_content))
            .returning(|_| {
                Ok((
                    *GenericArray::from_slice(&[0; 16]),
                    *GenericArray::from_slice(&[0; 12]),
                    vec![0; 16],
                ))
            });

        mock_db_client
            .expect_create_bin()
            .with(predicate::function(|x: &DbBin| x.content == vec![0; 16]))
            .returning(|_| Err(anyhow::anyhow!("db error").into()));

        let app_state = AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        };

        let req = CreateBinRequest {
            content: bin_content.to_string(),
        };

        let res = create_bin(State(Arc::new(app_state)), Json(req)).await;

        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), AppError::InternalServerError(_)));
    }
}
