use crate::Error;
use base64::prelude::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::pkcs8::EncodePrivateKey;
use reqwest::header::HeaderValue;
use serde::Serialize;
use std::collections::HashMap;
use std::ops::Add;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::{Origin, Url};

/// This is information used for the creation of VAPID authentication tokens within push messages.
/// A Vapid object is created and provided to a Push Service.
#[derive(Debug)]
pub struct Vapid {
    private_key: p256::ecdsa::SigningKey,

    identification: ServerIdentification,

    /// The maximum lifetime of a VAPID token. The maximum allowed lifetime is 24 hours. The
    /// system will cache a token for the specified lifetime given here before it creates a
    /// new token.
    token_lifetime: Duration,

    cached_tokens: Mutex<HashMap<Origin, VapidAuthorizationHeader>>,
}

impl Vapid {
    pub fn new(private_key: p256::ecdsa::SigningKey, identification: ServerIdentification) -> Self {
        Self::new_with_timeout(private_key, identification, Duration::from_mins(5))
    }

    pub fn new_with_timeout(
        private_key: p256::ecdsa::SigningKey,
        identification: ServerIdentification,
        token_lifetime: Duration,
    ) -> Self {
        if token_lifetime < Duration::from_mins(5) {
            panic!("Token lifetime cannot be less than 5 minutes");
        }
        if token_lifetime > Duration::from_hours(24) {
            panic!("Token lifetime cannot exceed 24 hours");
        }

        Self {
            private_key,
            identification,
            token_lifetime,
            cached_tokens: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn public_key(&self) -> &p256::ecdsa::VerifyingKey {
        self.private_key.verifying_key()
    }

    /// Obtain the authorization header that should be used for VAPID authenticated HTTP requests.
    /// The value returned may be placed directly into the `Authorization` header of HTTP requests
    /// to authenticate the server sending a Push message.
    pub(crate) fn authorization_header(
        &self,
        origin: &Origin,
    ) -> Result<VapidAuthorizationHeader, Error> {
        let mut cached_tokens = self
            .cached_tokens
            .lock()
            .map_err(|_| Error::FailedToLockTokenCache)?;

        let header = cached_tokens
            .remove(origin)
            .filter(|header| !header.requires_renewal())
            .unwrap_or_else(|| {
                let (token, expires_at) = self
                    .generate_token(origin)
                    .expect("Failed to generate VAPID token");
                let key = (&self).key_parameter();
                VapidAuthorizationHeader {
                    token,
                    key,
                    expires_at,
                }
            });

        cached_tokens.insert(origin.clone(), header.clone());

        Ok(header)
    }

    /// Generates a new token to be used for VAPID authenticated request to the specified request
    /// origin. This function will return the generated token and the expiration time for the token
    fn generate_token(&self, origin: &Origin) -> Result<(String, SystemTime), Error> {
        let header = Header::new(Algorithm::ES256);

        let now = SystemTime::now();
        let exp = now.add(self.token_lifetime);

        let claims = Claims {
            aud: origin.unicode_serialization(),
            sub: self.identification.subject.to_string(),
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

#[derive(Debug, Clone)]
pub struct ServerIdentification {
    subject: Url,
}

impl ServerIdentification {
    pub fn with_subject(subject: Url) -> Self {
        Self { subject }
    }
}

#[derive(Debug, Serialize)]
struct Claims {
    pub aud: String,

    pub sub: String,

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
        let header_value = format!("vapid t={},k={}", value.token, value.key);
        HeaderValue::from_str(&header_value).expect("Failed to create HeaderValue")
    }
}
