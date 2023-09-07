use crate::{app_error::AppError, models::AppState};
use axum::extract::{Path, State};
use std::sync::Arc;
use tracing::info;

pub async fn delete_bin(
    State(state): State<Arc<AppState>>,
    Path((id, edit_token)): Path<(String, String)>,
) -> Result<String, AppError> {
    info!("Deleting bin {}", id);

    let bin = state.db_client.get_bin(&id).await?;

    if bin.edit_token != edit_token {
        info!("Invalid edit token {id}", id = id);
        return Err(AppError::InvalidEditToken);
    }

    state.db_client.delete_bin(&id).await?;

    Ok("".to_string())
}

#[cfg(test)]
mod test {

    use crate::{
        app_error::AppError,
        commands::bin::delete_bin,
        database::MockDbClient,
        encrypt::MockBinEncrypter,
        models::{AppState, DbBin},
    };
    use anyhow::anyhow;
    use axum::extract::{Path, State};
    use mockall::predicate;
    use std::sync::Arc;

    fn create_mocks() -> (MockDbClient, MockBinEncrypter) {
        let mock_db_client = MockDbClient::new();
        let mock_encrypter = MockBinEncrypter::new();

        (mock_db_client, mock_encrypter)
    }

    #[tokio::test]
    async fn delete_bin_happy_path() {
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

        mock_db_client
            .expect_delete_bin()
            .with(predicate::eq("test".to_string()))
            .times(1)
            .returning(|_| Ok(()));

        let state = Arc::new(AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        });

        let response =
            delete_bin(State(state), Path(("test".to_string(), "test".to_string()))).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn delete_bin_find_fail() {
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

        let response =
            delete_bin(State(state), Path(("test".to_string(), "test".to_string()))).await;

        assert!(response.is_err());
        assert!(matches!(response.unwrap_err(), AppError::BinNotFound));
    }

    #[tokio::test]
    async fn delete_bin_invalid_edit_token() {
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

        let response = delete_bin(
            State(state),
            Path(("test".to_string(), "invalid".to_string())),
        )
        .await;

        assert!(response.is_err());
        assert!(matches!(response.unwrap_err(), AppError::InvalidEditToken));
    }

    #[tokio::test]
    async fn delete_bin_delete_fail() {
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

        mock_db_client
            .expect_delete_bin()
            .with(predicate::eq("test".to_string()))
            .times(1)
            .returning(|_| Err(AppError::InternalServerError(anyhow!("db error"))));

        let state = Arc::new(AppState {
            db_client: Box::new(mock_db_client),
            encrypter: Box::new(mock_encrypter),
        });

        let response =
            delete_bin(State(state), Path(("test".to_string(), "test".to_string()))).await;

        assert!(response.is_err());
        assert!(matches!(
            response.unwrap_err(),
            AppError::InternalServerError(_)
        ));
    }
}
