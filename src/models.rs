use serde::{Deserialize, Serialize};

use crate::{database::DbClient, encrypt::BinEncrypter};

// Create AppState with mongodb client
pub struct AppState {
    pub db_client: Box<dyn DbClient + Send + Sync>,
    pub encrypter: Box<dyn BinEncrypter + Send + Sync>,
}

/// A bin stored in MongoDB
#[derive(Serialize, Deserialize, Clone)]
pub struct DbBin {
    /// A cryptographically secure random id.
    pub id: String,
    /// The content of the bin.
    pub content: Vec<u8>,

    // Required to update/delete this bin
    pub edit_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateBinRequest {
    pub content: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateBinResponse {
    pub id: String,
    pub key: String,
    pub nonce: String,
    pub edit_token: String,
}
