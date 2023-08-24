use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes128Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};
use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Json, Router, Server,
};
use bson::doc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::trace::{self, TraceLayer};
use tracing::{info, Level};

// Create AppState with mongodb client
#[derive(Debug)]
struct AppState {
    database: mongodb::Database,
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
    let database = mongodb::Client::with_uri_str(mongo_uri)
        .await
        .unwrap()
        .database("bin");

    // create app state
    let app_state = Arc::new(AppState { database });

    let app = Router::new()
        .route("/api/create", put(create_bin))
        .route("/api/get/:id", get(get_bin))
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

    // For testing, use these curl commands:
    // curl -X PUT -d '{"content":"hello world"}' localhost:3000/api/create
    // curl -X GET localhost:3000/api/get?id=123
}

fn id_to_b58(x: u64) -> String {
    bs58::encode(x.to_be_bytes()).into_string()
}

fn b58_to_id(x: String) -> Option<u64> {
    bs58::decode(x).into_vec().ok().map(|x| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&x);
        u64::from_be_bytes(bytes)
    })
}

async fn create_bin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateBinRequest>,
) -> Json<CreateBinResponse> {
    let key = Aes128Gcm::generate_key(OsRng);
    let cipher = Aes128Gcm::new(&key);
    cipher.

    let nonce = Aes128Gcm::generate_nonce(OsRng);
    let ciphertext = cipher.encrypt(&nonce, req.content.as_bytes()).unwrap();

    let coll = state.database.collection::<DbBin>("bin");

    let id_b58 = id_to_b58(rand::random::<u64>());
    let edit_token_b58 = id_to_b58(rand::random::<u64>());

    info!("Creating bin with id {}", id_b58);
    info!("Encrypted content: {:?}", ciphertext);

    let bin = DbBin {
        id: id_b58.clone(),
        content: ciphertext,
        edit_token: edit_token_b58.clone(),
    };

    coll.insert_one(bin, None).await.unwrap();

    Json(CreateBinResponse {
        id: id_b58,
        key: bs58::encode(key).into_string(),
        nonce: bs58::encode(nonce).into_string(),
        edit_token: edit_token_b58,
    })
}

async fn get_bin(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> String {
    "dick".to_string()
}
async fn delete_bin() {}
async fn update_bin() {}

#[cfg(test)]
mod tests {
    // test the id stuff
    use super::*;

    #[test]
    fn id_b58_conversion() {
        for n in 0..100 {
            let x = rand::random::<u64>();
            assert_eq!(b58_to_id(id_to_b58(x)).unwrap(), x);
            assert_eq!(b58_to_id(id_to_b58(n)).unwrap(), n);
        }
    }
}
