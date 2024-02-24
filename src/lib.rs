use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader, FromRef},
    headers::{authorization::Bearer, Authorization},
    http::request::Parts,
    RequestPartsExt,
};
use jwt_simple::prelude::*;
use std::cell::OnceCell;
use serde::{Deserialize, Serialize};

use alw_core::Error;

#[derive(Debug)]
pub struct KeyStore{

}

#[derive(Debug, Clone)]
pub enum PubKey {
    RSA256(RS256PublicKey),
    ES256(ES256PublicKey),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub id: i32,
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    KeyStore: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|e| Error::Unauthorized(e.to_string()))?;

        let claim = KEY
            .get_unchecked()
            .public_key()
            .verify_token::<Claims>(bearer.token(), None)
            .map_err(|e| Error::Unauthorized(e.to_string()))?;

        Ok(claim.custom)
    }
}
