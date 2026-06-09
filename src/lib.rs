mod subscription;
mod vapid;

/// Implements the content encoding scheme specified in
/// [https://datatracker.ietf.org/doc/html/rfc8291](RFC 8291: Message Encryption for Web Push)
/// by taking an arbitrary piece of data and encrypting it using the given key. The implementation
/// only supports RFC8188 using a single record
mod rfc8188;

use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use p256::ecdsa::VerifyingKey;
use reqwest::header::HeaderMap;

pub use subscription::{AuthenticationSecret, Subscription};
pub use vapid::{ServerIdentification, Vapid};

/// The main component and entrypoint for sending web push
/// messages. Each Push Service should be configured with a private key that uniquely
/// identifies your application.
///
/// Additionally, it should be configured with some metadata that is used
/// to generate VAPID authentication token such as your contact e-mail address. This metadata will
/// be translated into JWT claims when generating tokens for your push messages.
#[derive(Debug)]
pub struct PushService {
    vapid: Vapid,
}

impl PushService {
    pub fn with_vapid(vapid: Vapid) -> Self {
        Self { vapid }
    }

    pub fn vapid_public_key(&self) -> &VerifyingKey {
        self.vapid.public_key()
    }

    /// Returns the public key for VAPID that should be supplied to the browser's `subscribe(..)`
    /// call.
    pub fn vapid_public_key_base64(&self) -> String {
        let public_key_bytes = self.vapid_public_key().to_sec1_bytes();
        BASE64_URL_SAFE_NO_PAD.encode(public_key_bytes)
    }

    pub async fn send<'a, 'b, 'c>(
        &'a self,
        subscription: &'b Subscription,
        content: impl Into<&'c [u8]>,
    ) -> Result<(), Error> {
        let client = reqwest::Client::new();

        let request = subscription
            .prepare_request(&client, content)
            .map_err(|e| Error::FailedToPrepareRequest(e))?;

        let header = self
            .vapid
            .authorization_header(&subscription.endpoint.origin())?;
        let mut headers = HeaderMap::new();
        headers.append("Authorization", header.into());
        let request = request.headers(headers);

        let response = request
            .send()
            .await
            .map_err(|e| Error::HttpRequestFailed(e))?;

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
    use crate::subscription::{AuthenticationSecret, Subscription};
    use crate::vapid::Vapid;
    use crate::{PushService, vapid};
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use ecdsa::SigningKey;
    use elliptic_curve::PublicKey;
    use elliptic_curve::pkcs8::DecodePrivateKey;
    use std::fs::read_to_string;
    use url::Url;

    #[tokio::test]
    async fn test_send() {
        let service = PushService::with_vapid(Vapid::new(
            SigningKey::from_pkcs8_pem(&read_to_string("vapid_test_2.pem").unwrap()).unwrap(),
            vapid::ServerIdentification::with_subject(
                url::Url::parse("mailto:test@test.test").unwrap(),
            ),
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
