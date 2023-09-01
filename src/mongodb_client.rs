use crate::{app_error::AppError, DbBin};
use anyhow::anyhow;
use async_trait::async_trait;
use bson::{doc, Binary, Bson};

#[async_trait]
pub trait DbClient {
    async fn create_bin(&self, bin: DbBin) -> Result<(), AppError>;
    async fn get_bin(&self, id: &str) -> Result<DbBin, AppError>;
    async fn update_bin(&self, id: &str, content: Vec<u8>) -> Result<(), AppError>;
    async fn delete_bin(&self, id: &str) -> Result<(), AppError>;
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
    async fn create_bin(&self, bin: DbBin) -> Result<(), AppError> {
        let coll = self.database.collection::<DbBin>("bin");
        coll.insert_one(bin, None).await.map_err(|e| anyhow!(e))?;

        Ok(())
    }

    async fn get_bin(&self, id: &str) -> Result<DbBin, AppError> {
        let coll = self.database.collection::<DbBin>("bin");
        let filter = doc! { "id": id };
        let bin = coll
            .find_one(filter, None)
            .await
            .map_err(|e| anyhow!(e))?
            .ok_or(AppError::BinNotFound)?;
        Ok(bin)
    }

    async fn update_bin(&self, id: &str, content: Vec<u8>) -> Result<(), AppError> {
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
        .map_err(|e| anyhow!(e))?;

        Ok(())
    }

    async fn delete_bin(&self, id: &str) -> Result<(), AppError> {
        let coll = self.database.collection::<DbBin>("bin");
        coll.delete_one(doc! { "id": id }, None)
            .await
            .map_err(|e| anyhow!(e))?;

        Ok(())
    }
}
