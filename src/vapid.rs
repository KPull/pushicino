use crate::Error;
use base64::prelude::*;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::pkcs8::EncodePrivateKey;
use reqwest::header::HeaderValue;
use std::ops::Add;
use std::time::{Duration, UNIX_EPOCH};
use url::Url;

/// This is information used for the creation of VAPID authentication tokens within push messages.
/// A Vapid object is created and provided to a Push Service.
pub(crate) struct Vapid {
    private_key: p256::ecdsa::SigningKey,
    identification: ServerIdentification,

    /// The maximum lifetime of a VAPID token. The maximum allowed lifetime is 24 hours. The
    /// system will cache a token for the specified lifetime given here before it creates a
    /// new token.
    token_lifetime: Duration,
}

impl Vapid {
    pub fn new(private_key: p256::ecdsa::SigningKey, identification: ServerIdentification) -> Self {
        Self::new_with_timeout(private_key, identification, Duration::from_hours(1))
    }

    pub fn new_with_timeout(
        private_key: p256::ecdsa::SigningKey,
        identification: ServerIdentification,
        token_lifetime: Duration,
    ) -> Self {
        if token_lifetime > Duration::from_hours(24) {
            panic!("Maximum token lifetime cannot exceed 24 hours");
        }

        Self {
            private_key,
            identification,
            token_lifetime,
        }
    }

    pub fn generate_authorization_header(&self) -> Result<VapidAuthorizationHeader, Error> {
        let token = (&self).generate_token()?;
        let key = (&self).key_parameter();

        Ok(VapidAuthorizationHeader { token, key })
    }

    fn generate_token(&self) -> Result<String, Error> {
        let header = Header::new(Algorithm::ES256);

        let now = std::time::SystemTime::now();
        let exp = now.add(self.token_lifetime);

        let claims = Claims {
            aud: self.identification.audience.clone().to_string(),
            sub: self
                .identification
                .subject
                .clone()
                .map(|url| url.to_string()),
            exp: exp
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::InvalidExpiryTime)?
                .as_secs(),
        };

        let private_key_der = self
            .private_key
            .to_pkcs8_der()
            .map_err(Error::FailedToWritePem)?;

        let encoding_key = EncodingKey::from_ec_der(private_key_der.to_bytes().as_slice());

        encode(&header, &claims, &encoding_key).map_err(Error::FailedToGenerateToken)
    }

    fn key_parameter(&self) -> String {
        let verifying_key = self.private_key.verifying_key();
        let public_key_bytes = verifying_key.to_sec1_bytes();
        BASE64_STANDARD.encode(public_key_bytes)
    }
}

#[derive(Debug)]
pub struct ServerIdentification {
    audience: Url,
    subject: Option<Url>,
}

impl ServerIdentification {
    pub fn with_audience(audience: Url) -> Self {
        Self {
            audience,
            subject: None,
        }
    }

    pub fn with_audience_and_subject(audience: Url, subject: Url) -> Self {
        Self {
            audience,
            subject: Some(subject),
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct Claims {
    pub aud: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    pub exp: u64,
}

#[derive(Debug)]
pub struct VapidAuthorizationHeader {
    token: String,
    key: String,
}

impl From<VapidAuthorizationHeader> for HeaderValue {
    fn from(value: VapidAuthorizationHeader) -> Self {
        HeaderValue::from_str(&format!("vapid t={},k={}", value.token, value.key))
            .expect("Failed to create HeaderValue")
    }
}
