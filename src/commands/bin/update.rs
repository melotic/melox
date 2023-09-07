use crate::{
    app_error::AppError,
    models::{AppState, CreateBinRequest, CreateBinResponse},
};
use axum::{
    debug_handler,
    extract::{Path, State},
    Json,
};
use std::sync::Arc;
use tracing::info;

#[debug_handler]
pub async fn update_bin(
    State(state): State<Arc<AppState>>,
    Path((id, edit_token)): Path<(String, String)>,
    Json(req): Json<CreateBinRequest>,
) -> Result<Json<CreateBinResponse>, AppError> {
    info!("Updating bin {id}", id = id);

    let bin = state.db_client.get_bin(&id).await?;

    if bin.edit_token != edit_token {
        info!("Invalid edit token {id}", id = id);
        return Err(AppError::InvalidEditToken);
    }

    let (key, nonce, ciphertext) = state.encrypter.generate_key_and_encrypt(&req.content)?;

    state.db_client.update_bin(&id, ciphertext).await?;
    info!("Updated bin {id}", id = id);

    Ok(Json(CreateBinResponse {
        id,
        key: bs58::encode(key).into_string(),
        nonce: bs58::encode(nonce).into_string(),
        edit_token,
    }))
}

#[cfg(test)]
mod test {

    use crate::{
        app_error::AppError,
        commands::bin::{get_bin, update_bin},
        database::MockDbClient,
        encrypt::MockBinEncrypter,
        models::{AppState, CreateBinRequest, DbBin},
    };
    use aes_gcm::aead::generic_array::GenericArray;
    use axum::{
        extract::{Path, State},
        Json,
    };
    use mockall::predicate;
    use std::sync::Arc;

    fn create_mocks() -> (MockDbClient, MockBinEncrypter) {
        let mock_db_client = MockDbClient::new();
        let mock_encrypter = MockBinEncrypter::new();

        (mock_db_client, mock_encrypter)
    }

    #[tokio::test]
    async fn update_bin_happy_path() {
        let (mut mock_db_client, mut mock_encrypter) = create_mocks();
        let bin_content = "hello world";
        let key = GenericArray::clone_from_slice(&[0; 16]);
        let nonce = GenericArray::clone_from_slice(&[0; 12]);

        let bin = DbBin {
            id: "test".to_string(),
            content: bin_content.as_bytes().to_vec(),
            edit_token: "test".to_string(),
        };

        mock_db_client
            .expect_get_bin()
            .with(predicate::eq("test".to_string()))
            .times(1)
            .returning(move |_| Ok(bin.clone()));

        mock_db_client
            .expect_update_bin()
            .with(
                predicate::eq("test".to_string()),
                predicate::eq(vec![0; 16]),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        mock_encrypter
            .expect_generate_key_and_encrypt()
            .with(predicate::eq(bin_content.to_string()))
            .times(1)
            .returning(move |_| Ok((key, nonce, bin_content.as_bytes().to_vec())));

        let state = Arc::new(AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        });

        let res = update_bin(
            State(state),
            Path(("test".to_string(), "test".to_string())),
            Json(CreateBinRequest {
                content: bin_content.to_string(),
            }),
        )
        .await
        .unwrap();

        assert_eq!(res.0.id, "test");
        assert_eq!(res.0.edit_token, "test");
    }

    #[tokio::test]
    async fn update_bin_find_fail() {
        let (mut mock_db_client, mock_encrypter) = create_mocks();

        mock_db_client
            .expect_get_bin()
            .with(predicate::eq("test".to_string()))
            .times(1)
            .returning(|_| Err(AppError::BinNotFound));

        let state = Arc::new(AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        });

        let res = update_bin(
            State(state),
            Path(("test".to_string(), "test".to_string())),
            Json(CreateBinRequest {
                content: "hello world".to_string(),
            }),
        )
        .await;

        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), AppError::BinNotFound));
    }

    #[tokio::test]
    async fn update_bin_invalid_edit_token() {
        let (mut mock_db_client, mock_encrypter) = create_mocks();

        let bin_content = "hello world";

        let bin = DbBin {
            id: "test".to_string(),
            content: bin_content.as_bytes().to_vec(),
            edit_token: "test".to_string(),
        };

        mock_db_client
            .expect_get_bin()
            .with(predicate::eq("test".to_string()))
            .times(1)
            .returning(move |_| Ok(bin.clone()));

        let state = Arc::new(AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        });

        let res = update_bin(
            State(state),
            Path(("test".to_string(), "invalid".to_string())),
            Json(CreateBinRequest {
                content: bin_content.to_string(),
            }),
        )
        .await;

        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), AppError::InvalidEditToken));
    }

    #[tokio::test]
    async fn update_bin_encrypt_fail() {
        let bin_content = "hello world";
        let (mut mock_db_client, mut mock_encrypter) = create_mocks();

        mock_db_client
            .expect_get_bin()
            .with(predicate::eq("test".to_string()))
            .times(1)
            .returning(move |_| {
                Ok(DbBin {
                    id: "test".to_string(),
                    content: bin_content.as_bytes().to_vec(),
                    edit_token: "test".to_string(),
                })
            });

        mock_encrypter
            .expect_generate_key_and_encrypt()
            .with(predicate::eq(bin_content.to_string()))
            .returning(|_| Err(anyhow::anyhow!("encrypt error").into()));

        let state = Arc::new(AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        });

        let res = update_bin(
            State(state),
            Path(("test".to_string(), "test".to_string())),
            Json(CreateBinRequest {
                content: bin_content.to_string(),
            }),
        )
        .await;

        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), AppError::InternalServerError(_)));
    }
}
