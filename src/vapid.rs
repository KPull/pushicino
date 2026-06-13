use crate::Error;
use base64::prelude::*;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use p256::SecretKey;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Add;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::{Origin, Url};

/// Establishes your server application's identity when sending Web Push messages.
///
/// VAPID stands for Voluntary Application Server Identification as defined in [`RFC 8292`]. It is
/// made up of a [`Subject`] that should typically be a `mailto` URL containing your e-mail address
/// and a [`VapidKey`] that is used to sign the VAPID token.
///
/// You must construct a [`Vapid`] object and supply it to every [`PushService`]. It is important
/// the same private key and subject e-mail address are used across application restarts and
/// in all running instances of your application.
///
/// When generating tokens for VAPID, the system will cache tokens for a specified lifetime. This
/// avoids having to create and sign tokens for messages sent in quick succession. You may select
/// the lifetime of cached tokens by using the [`Vapid::new_with_timeout`] constructor.
///
/// [`RFC 8292`]: https://datatracker.ietf.org/doc/html/rfc8292
#[derive(Debug)]
pub struct Vapid {
    private_key: VapidKey,

    subject: Subject,

    /// The maximum lifetime of a VAPID token. The maximum allowed lifetime is 24 hours. The
    /// system will cache a token for the specified lifetime given here before it creates a
    /// new token.
    token_lifetime: Duration,

    cached_tokens: Mutex<HashMap<Origin, VapidAuthorizationHeader>>,
}

impl Vapid {
    /// Creates a new [`Vapid`] object configured with the specified [`Subject`] and [`VapidKey`].
    ///
    /// A default token lifetime of 5 minutes is used.
    ///
    /// # Example
    ///
    /// Assuming you have a PEM-encoded ECDSA private key file named `vapid.pem`, you may
    /// initialise a [`Vapid`] as follows:
    ///
    /// ```rust
    /// use pushicino::{Vapid, Subject, VapidKey};
    ///
    /// Vapid::new(
    ///    Subject::parse("mailto:vapid@yourapplication.com")?,
    ///    VapidKey::load_from_file("vapid.pem")?,
    /// )
    /// ```
    pub fn new(subject: Subject, private_key: VapidKey) -> Self {
        Self::new_with_timeout(subject, private_key, Duration::from_mins(5))
    }

    /// Creates a new [`Vapid`] object configured with the specified [`Subject`], [`VapidKey`] and
    /// the configured cached token lifetime.
    ///
    /// # Panics
    ///
    /// Panics if the specified token lifetime is less than 5 minutes or greater than 24 hours.
    ///
    /// # Example
    ///
    /// Assuming you have a PEM-encoded ECDSA private key file named `vapid.pem`, you may
    /// initialise a [`Vapid`] as follows:
    ///
    /// ```rust
    /// use std::time::Duration;
    /// use pushicino::{Vapid, Subject, VapidKey};
    ///
    /// Vapid::new_with_timeout(
    ///    Subject::parse("mailto:vapid@yourapplication.com")?,
    ///    VapidKey::load_from_file("vapid.pem")?,
    ///    Duration::from_hours(2),
    /// )
    /// ```
    pub fn new_with_timeout(
        subject: Subject,
        private_key: VapidKey,
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
            subject,
            token_lifetime,
            cached_tokens: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn public_key(&self) -> &p256::ecdsa::VerifyingKey {
        self.private_key.0.verifying_key()
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
                let key = self.key_parameter();
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
            sub: self.subject.to_string(),
            exp: exp
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::InvalidExpiryTime)?
                .as_secs(),
        };

        let private_key_der = self
            .private_key
            .0
            .to_pkcs8_der()
            .map_err(Error::FailedToWritePem)?;

        let encoding_key = EncodingKey::from_ec_der(private_key_der.to_bytes().as_slice());

        encode(&header, &claims, &encoding_key)
            .map(|token| (token, exp))
            .map_err(Error::FailedToGenerateToken)
    }

    fn key_parameter(&self) -> String {
        let verifying_key = self.private_key.0.verifying_key();
        let public_key_bytes = verifying_key.to_sec1_bytes();
        BASE64_STANDARD_NO_PAD.encode(public_key_bytes)
    }
}

#[derive(Debug, Serialize)]
struct Claims {
    pub aud: String,

    pub sub: String,

    pub exp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VapidAuthorizationHeader {
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

/// An [`Url`] which uses the `mailto:` scheme and is suitable for use as the `sub` claim
/// in VAPID-generated tokens.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Subject(Url);

impl Subject {
    /// Constructs a new [`Subject`] directly from a given string slice.
    ///
    /// This function will return an error if the provided string value is not a valid URL that
    /// uses the `mailto:` scheme.
    ///
    /// # Example
    ///
    /// ```rust
    /// use pushicino::Subject;
    ///
    /// let subject = Subject::parse("mailto:vapid@yourapplication.com")?
    /// ```
    pub fn parse(value: &str) -> Result<Self, SubjectError> {
        let url = Url::parse(value).map_err(SubjectError::InvalidUrl)?;

        Self::try_from_url(url)
    }

    /// Constructs a new [`Subject`] from a parsed [`Url`].
    ///
    /// This function will return an error if the provided does not use the `mailto:` scheme.
    ///
    /// # Example
    ///
    /// ```rust
    /// use url::Url;
    /// use pushicino::Subject;
    ///
    /// let subject = Subject::try_from_url(Url::parse("mailto:vapid@yourapplication.com")?)?
    /// ```
    pub fn try_from_url(url: Url) -> Result<Self, SubjectError> {
        if url.scheme() != "mailto" {
            return Err(SubjectError::UrlNotMailto);
        }

        Ok(Subject(url))
    }
}

impl TryFrom<&str> for Subject {
    type Error = SubjectError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<Url> for Subject {
    type Error = SubjectError;

    fn try_from(value: Url) -> Result<Self, Self::Error> {
        Self::try_from_url(value)
    }
}

impl Display for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<Url> for Subject {
    fn as_ref(&self) -> &Url {
        &self.0
    }
}

/// The set of possible errors that can be returned by the [`Subject`] constructors.
#[derive(Debug)]
pub enum SubjectError {
    /// There was a problem parsing the given URL
    InvalidUrl(url::ParseError),

    /// The given URL does not use the `mailto:` scheme
    UrlNotMailto,
}

/// The secret key used to sign generated VAPID tokens.
///
/// This struct is a simple wrapper around a [`SigningKey`] but with some extra utility
/// functions for constructing the key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VapidKey(SigningKey);

impl VapidKey {
    /// Load a VAPID Key that is stored in a PEM file on disk.
    ///
    /// Supply the file path to load the key from.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, VapidKeyLoadFromFileError> {
        let contents =
            std::fs::read_to_string(path).map_err(VapidKeyLoadFromFileError::FileReadError)?;

        Ok(Self::load_from_pem(&contents)?)
    }

    /// Load a VAPID key from a PEM-encoded string.
    ///
    /// Supply the entire string to load the key from.
    pub fn load_from_pem(contents: &str) -> Result<Self, VapidKeyLoadFromPemError> {
        let key = SecretKey::from_sec1_pem(contents)
            .map_err(VapidKeyLoadFromPemError::InvalidKeyFormat)?;

        Ok(Self(key.into()))
    }
}

impl AsRef<SigningKey> for VapidKey {
    fn as_ref(&self) -> &SigningKey {
        &self.0
    }
}

impl<T: Into<SigningKey>> From<T> for VapidKey {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

#[derive(Debug)]
pub enum VapidKeyLoadFromFileError {
    FileReadError(std::io::Error),
    InvalidKeyFormat(elliptic_curve::Error),
}

impl From<VapidKeyLoadFromPemError> for VapidKeyLoadFromFileError {
    fn from(value: VapidKeyLoadFromPemError) -> Self {
        match value {
            VapidKeyLoadFromPemError::InvalidKeyFormat(e) => Self::InvalidKeyFormat(e),
        }
    }
}

pub enum VapidKeyLoadFromPemError {
    InvalidKeyFormat(elliptic_curve::Error),
}
