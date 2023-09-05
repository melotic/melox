#[cfg(test)]
use mockall::{automock, mock, predicate::*};

use crate::{app_error::AppError, models::DbBin};
use async_trait::async_trait;

pub mod mongodb;

#[cfg_attr(test, automock)]
#[async_trait]
pub trait DbClient {
    async fn create_bin(&self, bin: DbBin) -> Result<(), AppError>;
    async fn get_bin(&self, id: &str) -> Result<DbBin, AppError>;
    async fn update_bin(&self, id: &str, content: Vec<u8>) -> Result<(), AppError>;
    async fn delete_bin(&self, id: &str) -> Result<(), AppError>;
}
