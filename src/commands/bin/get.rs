use crate::{app_error::AppError, models::AppState};
use aes_gcm::aead::generic_array::GenericArray;
use anyhow::anyhow;
use axum::extract::{Path, State};
use std::sync::Arc;
use tracing::info;

pub async fn get_bin(
    State(state): State<Arc<AppState>>,
    Path((id, key, nonce)): Path<(String, String, String)>,
) -> Result<String, AppError> {
    info!("Getting bin {}", id);

    let bin = state.db_client.get_bin(&id).await?;

    let key = bs58::decode(key).into_vec().map_err(|e| anyhow!(e))?;
    let nonce = bs58::decode(nonce).into_vec().map_err(|e| anyhow!(e))?;

    let plaintext = state.encrypter.decrypt(
        *GenericArray::from_slice(&key),
        *GenericArray::from_slice(&nonce),
        &bin.content,
    )?;

    Ok(plaintext)
}

#[cfg(test)]
mod test {

    use crate::{
        app_error::AppError,
        commands::bin::get_bin,
        database::MockDbClient,
        encrypt::MockBinEncrypter,
        models::{AppState, DbBin},
    };
    use aes_gcm::aead::generic_array::GenericArray;
    use axum::extract::{Path, State};
    use mockall::predicate;
    use std::sync::Arc;

    fn create_mocks() -> (MockDbClient, MockBinEncrypter) {
        let mock_db_client = MockDbClient::new();
        let mock_encrypter = MockBinEncrypter::new();

        (mock_db_client, mock_encrypter)
    }

    #[tokio::test]
    async fn get_bin_happy_path() {
        let (mut mock_db_client, mut mock_encrypter) = create_mocks();

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

        mock_encrypter
            .expect_decrypt()
            .with(
                predicate::eq(*GenericArray::from_slice(&[0; 16])),
                predicate::eq(*GenericArray::from_slice(&[0; 12])),
                predicate::eq(bin_content.as_bytes().to_vec()),
            )
            .times(1)
            .returning(|_, _, _| Ok(bin_content.to_string()));

        let state = Arc::new(AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        });

        let response = get_bin(
            State(state),
            Path((
                "test".to_string(),
                bs58::encode([0; 16]).into_string(),
                bs58::encode([0; 12]).into_string(),
            )),
        )
        .await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn get_bin_find_fail() {
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

        let response = get_bin(
            State(state),
            Path((
                "test".to_string(),
                bs58::encode([0; 16]).into_string(),
                bs58::encode([0; 12]).into_string(),
            )),
        )
        .await;

        assert!(response.is_err());
        assert!(matches!(response.unwrap_err(), AppError::BinNotFound));
    }

    #[tokio::test]
    async fn get_bin_decrypt_fail() {
        let (mut mock_db_client, mut mock_encrypter) = create_mocks();

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

        mock_encrypter
            .expect_decrypt()
            .with(
                predicate::eq(*GenericArray::from_slice(&[0; 16])),
                predicate::eq(*GenericArray::from_slice(&[0; 12])),
                predicate::eq(bin_content.as_bytes().to_vec()),
            )
            .times(1)
            .returning(|_, _, _| Err(anyhow::anyhow!("decrypt error").into()));

        let state = Arc::new(AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        });

        let response = get_bin(
            State(state),
            Path((
                "test".to_string(),
                bs58::encode([0; 16]).into_string(),
                bs58::encode([0; 12]).into_string(),
            )),
        )
        .await;

        assert!(response.is_err());
        assert!(matches!(
            response.unwrap_err(),
            AppError::InternalServerError(_)
        ));
    }

    #[tokio::test]
    async fn get_bin_invalid_key() {
        let (mut mock_db_client, mut mock_encrypter) = create_mocks();

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

        mock_encrypter
            .expect_decrypt()
            .with(
                predicate::eq(*GenericArray::from_slice(&[0; 16])),
                predicate::eq(*GenericArray::from_slice(&[0; 12])),
                predicate::eq(bin_content.as_bytes().to_vec()),
            )
            .times(1)
            .returning(|_, _, _| Err(anyhow::anyhow!("decrypt error").into()));

        let state = Arc::new(AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        });

        let response = get_bin(
            State(state),
            Path((
                "test".to_string(),
                "invalid".to_string(),
                bs58::encode([0; 12]).into_string(),
            )),
        )
        .await;

        assert!(response.is_err());
        assert!(matches!(
            response.unwrap_err(),
            AppError::InternalServerError(_)
        ));
    }
}
