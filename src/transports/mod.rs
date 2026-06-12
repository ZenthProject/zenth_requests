use async_trait::async_trait;
use crate::{
    request::Request, 
    response::Response,
    errors::errors::ReqError
};

pub mod http;
pub mod tor;
pub mod lokinet;

#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, req: Request) -> Result<Response, ReqError>;
    async fn recv(&self) -> Result<Response, ReqError>;
}