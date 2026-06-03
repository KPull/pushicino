use crate::Error;
use base64::prelude::*;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use p256::pkcs8::EncodePrivateKey;
use reqwest::header::HeaderValue;
use std::ops::Add;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

/// This is information used for the creation of VAPID authentication tokens within push messages.
/// A Vapid object is created and provided to a Push Service.
pub struct Vapid {
    private_key: p256::ecdsa::SigningKey,
    identification: ServerIdentification,

    /// The maximum lifetime of a VAPID token. The maximum allowed lifetime is 24 hours. The
    /// system will cache a token for the specified lifetime given here before it creates a
    /// new token.
    token_lifetime: Duration,

    cached_token: Mutex<Option<VapidAuthorizationHeader>>,
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
        if token_lifetime < Duration::from_hours(1) {
            panic!("Token lifetime cannot be less than 1 hour");
        }
        if token_lifetime > Duration::from_hours(24) {
            panic!("Token lifetime cannot exceed 24 hours");
        }

        Self {
            private_key,
            identification,
            token_lifetime,
            cached_token: Mutex::new(None),
        }
    }

    /// Obtain the authorization header that should be used for VAPID authenticated HTTP requests.
    /// The value returned may be placed directly into the `Authorization` header of HTTP requests
    /// to authenticate the server sending a Push message.
    pub fn authorization_header(&self) -> Result<VapidAuthorizationHeader, Error> {
        let mut lock = self
            .cached_token
            .lock()
            .map_err(|_| Error::FailedToLockTokenCache)?;

        match lock.as_mut() {
            None => {
                let (token, expires_at) = self.generate_token()?;
                let key = (&self).key_parameter();
                let header = VapidAuthorizationHeader {
                    token,
                    key,
                    expires_at,
                };
                *lock = Some(header.clone());
                Ok(header)
            }
            Some(cached) if cached.requires_renewal() => {
                let (token, expires_at) = self.generate_token()?;
                let key = (&self).key_parameter();
                let header = VapidAuthorizationHeader {
                    token,
                    key,
                    expires_at,
                };
                *lock = Some(header.clone());
                Ok(header)
            }
            Some(cached) => {
                Ok(cached.clone())
            }
        }
    }

    /// Generates a new token to be used for VAPID authenticated requests. This function will
    /// return the generated token and the expiration time for the token
    fn generate_token(&self) -> Result<(String, SystemTime), Error> {
        let header = Header::new(Algorithm::ES256);

        let now = SystemTime::now();
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

        encode(&header, &claims, &encoding_key)
            .map(|token| (token, exp))
            .map_err(Error::FailedToGenerateToken)
    }

    fn key_parameter(&self) -> String {
        let verifying_key = self.private_key.verifying_key();
        let public_key_bytes = verifying_key.to_sec1_bytes();
        BASE64_STANDARD_NO_PAD.encode(public_key_bytes)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VapidAuthorizationHeader {
    token: String,
    key: String,

    expires_at: SystemTime,
}

impl VapidAuthorizationHeader {
    /// Returns true if the token is due for renewal.
    /// This function will return true if the expiry time has elapsed or is close to elapsing soon.
    pub fn requires_renewal(&self) -> bool {
        const RENEWAL_EARLY_PERIOD: Duration = Duration::from_mins(1);
        self.expires_at - RENEWAL_EARLY_PERIOD < SystemTime::now()
    }
}

impl From<VapidAuthorizationHeader> for HeaderValue {
    fn from(value: VapidAuthorizationHeader) -> Self {
        HeaderValue::from_str(&format!("vapid t={},k={}", value.token, value.key))
            .expect("Failed to create HeaderValue")
    }
}
