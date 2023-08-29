use crate::DbBin;
use async_trait::async_trait;
use axum::http::StatusCode;
use bson::{doc, Binary, Bson};

#[async_trait]
pub trait DbClient {
    async fn create_bin(&self, bin: DbBin) -> Result<(), StatusCode>;
    async fn get_bin(&self, id: &str) -> Result<DbBin, StatusCode>;
    async fn update_bin(&self, id: &str, content: Vec<u8>) -> Result<(), StatusCode>;
    async fn delete_bin(&self, id: &str) -> Result<(), StatusCode>;
}

pub struct MongoDbClient {
    database: mongodb::Database,
}

impl MongoDbClient {
    pub fn new(database: mongodb::Database) -> MongoDbClient {
        MongoDbClient { database }
    }
}

#[async_trait]
impl DbClient for MongoDbClient {
    async fn create_bin(&self, bin: DbBin) -> Result<(), StatusCode> {
        let coll = self.database.collection::<DbBin>("bin");
        coll.insert_one(bin, None)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(())
    }

    async fn get_bin(&self, id: &str) -> Result<DbBin, StatusCode> {
        let coll = self.database.collection::<DbBin>("bin");
        let filter = doc! { "id": id };
        let bin = coll
            .find_one(filter, None)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::NOT_FOUND)?;
        Ok(bin)
    }

    async fn update_bin(&self, id: &str, content: Vec<u8>) -> Result<(), StatusCode> {
        let coll = self.database.collection::<DbBin>("bin");

        let content = Bson::Binary(Binary {
            subtype: bson::spec::BinarySubtype::Encrypted,
            bytes: content,
        });

        coll.update_one(
            doc! { "id": id },
            doc! { "$set": { "content": content } },
            None,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(())
    }

    async fn delete_bin(&self, id: &str) -> Result<(), StatusCode> {
        let coll = self.database.collection::<DbBin>("bin");
        coll.delete_one(doc! { "id": id }, None)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(())
    }
}
