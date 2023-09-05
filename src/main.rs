mod app_error;
mod commands;
mod database;
mod encrypt;
pub mod models;

use std::sync::Arc;

use crate::database::mongodb::MongoDbClient;
use axum::{
    routing::{delete, get, post, put},
    Router, Server,
};
use commands::bin::*;
use encrypt::Aes128BinEncryption;
use models::AppState;
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

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
