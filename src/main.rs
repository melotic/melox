mod encrypt;
mod mongodb_client;

use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes128Gcm, // Or `Aes128Gcm`
    Nonce,
};
use axum::{
    debug_handler,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router, Server,
};
use bson::doc;
use encrypt::{Aes128BinEncryption, BinEncrypter};
use mongodb_client::{DbClient, MongoDbClient};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::trace::{self, TraceLayer};
use tracing::{info, Level};

// Create AppState with mongodb client
struct AppState {
    db_client: Box<dyn DbClient + Send + Sync>,
    encrypter: Box<dyn BinEncrypter + Send + Sync>,
}

/// A bin stored in MongoDB
#[derive(Serialize, Deserialize)]
struct DbBin {
    /// A cryptographically secure random id.
    id: String,
    /// The content of the bin.
    content: Vec<u8>,

    // Required to update/delete this bin
    edit_token: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CreateBinRequest {
    content: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CreateBinResponse {
    id: String,
    key: String,
    nonce: String,
    edit_token: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().pretty().init();

    // hardcode MONGO_URI for now
    let mongo_uri = "mongodb://admin:password@localhost:27017";

    // connect to mongodb through MONGO_URI env var
    let db_client = MongoDbClient::new(
        mongodb::Client::with_uri_str(mongo_uri)
            .await
            .unwrap()
            .database("bin"),
    );

    // create app state
    let app_state = Arc::new(AppState {
        db_client: Box::new(db_client),
        encrypter: Box::new(Aes128BinEncryption),
    });

    let app = Router::new()
        .route("/api/create", put(create_bin))
        .route("/api/get/:id/:key/:nonce", get(get_bin))
        .route("/api/delete/:id/:edit_token", delete(delete_bin))
        .route("/api/update/:id/:edit_token", post(update_bin))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state(app_state);

    Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();

    // Curl commands for testing:
    // curl -X PUT -d '{"content":"hello world"}' localhost:3000/api/create
}

fn id_to_b58(x: u64) -> String {
    bs58::encode(x.to_be_bytes()).into_string()
}

#[debug_handler]
async fn create_bin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateBinRequest>,
) -> Json<CreateBinResponse> {
    let (key, nonce, ciphertext) = state
        .encrypter
        .generate_key_and_encrypt(&req.content)
        .unwrap();
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

    state.db_client.create_bin(bin).await.unwrap();

    Json(CreateBinResponse {
        id,
        key: bs58::encode(key).into_string(),
        nonce: bs58::encode(nonce).into_string(),
        edit_token,
    })
}

async fn get_bin(
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
async fn update_bin(
    State(state): State<Arc<AppState>>,
    Query((id, edit_token)): Query<(String, String)>,
    Json(req): Json<CreateBinRequest>,
) -> Result<Json<CreateBinResponse>, StatusCode> {
    info!("Updating bin {}", id);

    let bin = state.db_client.get_bin(&id).await.unwrap();

    if bin.edit_token != edit_token {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (key, nonce, ciphertext) = state
        .encrypter
        .generate_key_and_encrypt(&req.content)
        .unwrap();

    state.db_client.update_bin(&id, ciphertext).await.unwrap();

    Ok(Json(CreateBinResponse {
        id,
        key: bs58::encode(key).into_string(),
        nonce: bs58::encode(nonce).into_string(),
        edit_token,
    }))
}

async fn delete_bin(
    State(state): State<Arc<AppState>>,
    Path((id, edit_token)): Path<(String, String)>,
) -> Result<String, StatusCode> {
    info!("Deleting bin {}", id);

    let bin = state.db_client.get_bin(&id).await.unwrap();

    if bin.edit_token != edit_token {
        return Err(StatusCode::UNAUTHORIZED);
    }

    state.db_client.delete_bin(&id).await.unwrap();

    Ok("".to_string())
}
