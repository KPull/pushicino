//! This crate provides the tools necessary for your application to send Web Push messages
//! in accordance with [`RFC 8030`].
//!
//! In addition to sending Push messages, this crate also handles:
//! * the generation of valid Voluntary Application Server Identification (VAPID) tokens,
//!   as required, in accordance with [`RFC 8292`] for any messages you send; and,
//! * the proper encryption of message content you send, using AES128GCM, in accordance with
//!   [`RFC 8291`].
//!
//! # Setup a Push Service
//!
//! Before your application can accept subscriptions from web browsers and send messages, you must
//! first initialize a [`PushService`] with an ECDSA private key and metadata that will be used to
//! generate VAPID tokens. The ECDSA private key and metadata you use represents your
//! application's "identity" to servers that deliver your push message: this means you should use
//! the same private key across restarts of your application and across multiple running
//! instances of your application.
//!
//! The OpenSSL suite can be used to generate an ECDSA private key for use with this library as
//! follows:
//!
//! ```bash
//! openssl ecparam -name secp256r1 -genkey -noout -out vapid.pem
//! ```
//!
//! This should have created a file called `vapid.pem` containing the private key. Keep it secret:
//! losing it could allow an attacker to send push messages as if they were coming from your
//! application.
//!
//! Then, create a [`PushService`] as follows:
//!
//! ```rust
//! use pushicino::{PushService, Vapid, Subject, VapidKey};
//! let service = PushService::new(Vapid::new(
//!   Subject::parse("mailto:vapid@yourapplication.com")?,
//!   VapidKey::load_from_file("vapid.pem")?,
//! ));
//!
//! // If you're using Axum, you should put the PushService into your application's state object
//! ```
//!
//! If you're using a web framework, like Axum, you should put the [`PushService`] that we created
//! here into your application's state and that can be accessed by your application's route
//! handlers.
//!
//! # VAPID Endpoint
//!
//! Frontend applications running on the browser will require your [`PushService`]'s public key.
//! You should create an endpoint that serves this public key, in Base64 encoding, to the frontend.
//! For example, in Axum, you could do:
//!
//! ```rust
//! use std::sync::Arc;
//! use axum::http::StatusCode;
//! use axum::extract::State;
//! use axum::Json;
//! use serde::Serialize;
//! use pushicino::PushService;
//!
//! struct ApplicationState {
//!     push_service: PushService,
//! }
//!
//! #[derive(Serialize)]
//! struct ApplicationConfiguration {
//!     vapid_public_key: String,
//! }
//!
//! // Create a request handler that will serve the push service's public key in Base64 encoding
//! pub async fn application_configuration(State(state): State<Arc<ApplicationState>>)
//!     -> Result<Json<ApplicationConfiguration>, StatusCode> {
//!     Ok(Json(ApplicationConfiguration {
//!          vapid_public_key: state.push_service.vapid_public_key_base64(),
//!     }))
//! }
//!
//! // Don't forget to register the `application_configuration` handler with your Axum router!
//! ```
//!
//! Feel free to use any other method, instead of the one suggested above, to transfer the public
//! key to the frontend.
//!
//! # Subscriptions Endpoints
//!
//! When the user's browser confirms they would like to receive push messages from your application,
//! they will need to send the subscription details to your application. You can receive this
//! information by setting up an endpoint to receive this information.
//!
//! [`Subscription`] implements the [`serde::Deserialize`] trait (from the `serde` crate) and it matches
//! the exact object returned by the [`PushSubscription.toJSON()`] method of the user agent. This
//! allows you to accept a [`Subscription`] directly from your request handler.
//!
//! For example, in Axum, you could do:
//!
//! ```rust
//! use std::sync::Arc;
//! use axum::http::StatusCode;
//! use axum::extract::State;
//! use axum::Json;
//! use serde::Serialize;
//! use pushicino::{PushService, Subscription};
//!
//! struct ApplicationState {
//!     push_service: PushService,
//! }
//!
//! async fn subscribe(
//!  State(application): State<Arc<ApplicationState>>,
//!  Json(request): Json<Subscription>,
//! ) -> Result<(), StatusCode> {
//!   // At this point, you should persist the Subscription into a database or some other storage
//!
//!   // Send a Web Push message immediately to the user, thanking them for subscribing!
//!   application.push_service.send(&request, "Hello, thanks for subscribing!".as_bytes())
//!    .await.unwrap();
//!
//!   Ok(())
//! }
//!
//! // Don't forget to register the `subscribe` handler with your Axum router!
//! ```
//!
//! **It is your responsibility to persist the [`Subscription`] into storage** ([`Subscription`]
//! implements the [`serde::Serialize`] trait). It is highly recommended that you associate the user's
//! identity alongside the [`Subscription`] in case you wish to send Web Push messages to specific
//! users.
//!
//! [`RFC 8030`]: https://datatracker.ietf.org/doc/html/rfc8030
//! [`RFC 8292`]: https://datatracker.ietf.org/doc/html/rfc8292
//! [`RFC 8291`]: https://datatracker.ietf.org/doc/html/rfc8291
//! [`PushSubscription.toJSON()`]: https://developer.mozilla.org/en-US/docs/Web/API/PushSubscription/toJSON
//!
//!
mod rfc8188;
mod subscription;
mod vapid;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::VerifyingKey;
use reqwest::header::HeaderMap;
pub use subscription::{AuthenticationSecret, Subscription};
pub use vapid::{Subject, Vapid, VapidKey};

/// The main entrypoint for sending Web Push messages.
///
/// Each Push Service should be configured with a [`Vapid`] object that uniquely identifies your
/// application. It is important that the same [`Vapid`] configuration (private key and subject)
/// is reused across application restarts and across multiple running instances of your application.
#[derive(Debug)]
pub struct PushService {
    vapid: Vapid,
    default_ttl: u64,
}

impl PushService {
    /// Initialises a new Push Service that can be used for sending Web Push messages.
    ///
    /// You need to configure a [`Vapid`] object containing your server's identification. This
    /// constructor will use a default TTL value of '60'. If you wish to customize the default TTL
    /// value, use [`PushService::new_with_default_ttl`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// let service = PushService::new(
    ///   Vapid::new(
    ///     Subject::parse("mailto:vapid@example.com")?,
    ///     VapidKey::load_from_file("vapid.pem")?,
    ///   ),
    /// );
    /// ```
    pub fn new(vapid: Vapid) -> Self {
        Self::new_with_default_ttl(vapid, 60)
    }

    /// Initialises a new Push Service that can be used for sending Web Push messages, supplying
    /// a default TTL value for messages sent by this service.
    ///
    /// You need to configure a [`Vapid`] object containing your server's identification. This
    /// constructor takes a TTL value which will be added to messages sent by this service.
    pub fn new_with_default_ttl(vapid: Vapid, default_ttl: u64) -> Self {
        Self { vapid, default_ttl }
    }

    /// Returns the public key for VAPID used to identify your server in the form of a
    /// [`VerifyingKey`].
    ///
    /// Use [`PushService::vapid_public_key_base64`] instead to get the public key as a
    /// Base64-encoded that is suitable for returning to the user's browser.
    pub fn vapid_public_key(&self) -> &VerifyingKey {
        self.vapid.public_key()
    }

    /// Returns the public key for VAPID that should be supplied to the browser's `subscribe(..)`
    /// call when the end-user wants to register a new subscription
    pub fn vapid_public_key_base64(&self) -> String {
        let public_key_bytes = self.vapid_public_key().to_sec1_bytes();
        BASE64_URL_SAFE_NO_PAD.encode(public_key_bytes)
    }

    /// Sends a Web Push message to the given Subscription.
    ///
    /// You may supply any message object that can be converted into a byte slice using
    /// [`Into<[u8]>::into`]. The Push Service will take care to generate a VAPID token, if
    /// necessary, to be included within the Web Push request, and to encrypt the message in
    /// accordance with [`RFC 8291`].
    ///
    /// This version of the `send` method uses the default TTL value that was supplied when the
    /// [`PushService`] was created.
    ///
    /// # Example
    ///
    /// ```rust
    /// use pushicino::{PushService, Vapid, Subject, VapidKey}
    /// let service = PushService::new(
    ///   Vapid::new(
    ///     Subject::parse("mailto:vapid@example.com")?,
    ///     VapidKey::load_from_file("vapid.pem")?,
    ///   ),
    /// );
    /// ```
    ///
    /// [`RFC 8291`]: https://datatracker.ietf.org/doc/html/rfc8291
    pub async fn send<'a, 'b, 'c>(
        &'a self,
        subscription: &'b Subscription,
        content: impl Into<&'c [u8]>,
    ) -> Result<(), Error> {
        self.send_with_ttl(subscription, self.default_ttl, content)
            .await
    }

    /// Sends a Web Push message to the given Subscription, specifying the TTL value to be used.
    ///
    /// You may supply any message object that can be converted into a byte slice using
    /// [`Into<[u8]>::into`]. The Push Service will take care to generate a VAPID token, if
    /// necessary, to be included within the Web Push request, and to encrypt the message in
    /// accordance with [`RFC 8291`].
    ///
    /// This version of the `send` method uses the TTL value supplied in the parameters, instead
    /// of the [`PushService`]'s default value.
    ///
    /// [`RFC 8291`]: https://datatracker.ietf.org/doc/html/rfc8291
    pub async fn send_with_ttl<'a, 'b, 'c>(
        &'a self,
        subscription: &'b Subscription,
        ttl: u64,
        content: impl Into<&'c [u8]>,
    ) -> Result<(), Error> {
        let client = reqwest::Client::new();

        let request = subscription
            .prepare_request(&client, ttl, content)
            .map_err(Error::FailedToPrepareRequest)?;

        let header = self
            .vapid
            .authorization_header(&subscription.endpoint.origin())?;
        let mut headers = HeaderMap::new();
        headers.append("Authorization", header.into());
        let request = request.headers(headers);

        let response = request.send().await.map_err(Error::HttpRequestFailed)?;

        let response_body = response.text().await.unwrap_or_default();
        println!("RESPONSE_BODY: {}", response_body);

        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidExpiryTime,
    FailedToLockTokenCache,
    FailedToPrepareRequest(subscription::Error),
    FailedToWritePem(p256::pkcs8::Error),
    InvalidEncodingKey(jsonwebtoken::errors::Error),
    FailedToGenerateToken(jsonwebtoken::errors::Error),
    InvalidHttpHeader(reqwest::header::InvalidHeaderValue),
    HttpRequestFailed(reqwest::Error),
}

#[cfg(test)]
mod tests {
    use crate::PushService;
    use crate::subscription::{AuthenticationSecret, Subscription};
    use crate::vapid::{Subject, Vapid, VapidKey};
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use elliptic_curve::PublicKey;
    use url::Url;

    #[tokio::test]
    async fn test_send() {
        let service = PushService::new(Vapid::new(
            Subject::parse("mailto:test@test.test").unwrap(),
            VapidKey::load_from_file("vapid_test_2.pem").unwrap(),
        ));
        let subscription = Subscription::new(
            Url::parse("https://www.postb.in/1780346657084-9427918170113").unwrap(),
            None,
                AuthenticationSecret(BASE64_URL_SAFE_NO_PAD.decode("BTBZMqHH6r4Tts7J_aSIgg").unwrap()
                    .try_into().unwrap()),
            PublicKey::from_sec1_bytes(&BASE64_URL_SAFE_NO_PAD.decode("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8").unwrap()).unwrap(),
        );
        service
            .send(&subscription, String::from("Hello, world!").as_bytes())
            .await
            .unwrap();
    }
}
