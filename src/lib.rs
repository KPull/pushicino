mod subscription;
mod vapid;

/// Implements the content encoding scheme specified in
/// [https://datatracker.ietf.org/doc/html/rfc8291](RFC 8291: Message Encryption for Web Push)
/// by taking an arbitrary piece of data and encrypting it using the given key. The implementation
/// only supports RFC8188 using a single record
mod rfc8188;

use reqwest::header::HeaderMap;
use subscription::{Subscription, SubscriptionRequest};

/// The main component and entrypoint for managing web push subscriptions and sending web push
/// messages. Each Push Service should be configured with a private key that uniquely
/// identifies your application.
///
/// Additionally, it should be configured with some metadata that is used
/// to generate VAPID authentication token such as your contact e-mail address. This metadata will
/// be translated into JWT claims when generating tokens for your push messages.
struct PushService {
    vapid: vapid::Vapid,
}

impl PushService {
    pub fn with_vapid(vapid: vapid::Vapid) -> Self {
        Self { vapid }
    }

    pub async fn subscribe(
        &self,
        request: SubscriptionRequest,
    ) -> Result<Subscription, subscription::Error> {
        // TODO: Persist the subscription into durable storage so that we can send to it later on
        todo!()
    }

    pub async fn send<'a, 'b>(
        &'a self,
        subscription: &'a Subscription,
        content: impl Into<&'b [u8]>,
    ) -> Result<(), Error> {
        let client = reqwest::Client::new();

        let request = subscription
            .prepare_request(&client, content)
            .map_err(|e| Error::FailedToPrepareRequest(e))?;

        let header = self.vapid.authorization_header()?;
        let mut headers = HeaderMap::new();
        headers.append("Authorization", header.into());
        let request = request.headers(headers);

        request.send().await
            .map_err(|e| Error::HttpRequestFailed(e))?;

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
    use crate::subscription::{AuthenticationSecret, SubscriptionRequest, SubscriptionSecrets};
    use crate::vapid::Vapid;
    use crate::{subscription, vapid, PushService};
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use base64::Engine;
    use ecdsa::SigningKey;
    use elliptic_curve::pkcs8::DecodePrivateKey;
    use elliptic_curve::PublicKey;
    use std::fs::read_to_string;
    use url::Url;

    #[tokio::test]
    async fn test_send() {
        let service = PushService::with_vapid(Vapid::new(
            SigningKey::from_pkcs8_pem(&read_to_string("vapid_test_2.pem").unwrap()).unwrap(),
            vapid::ServerIdentification::with_audience(
                url::Url::parse("https://example.com").unwrap(),
            ),
        ));
        let subscription = SubscriptionRequest::new(
            Url::parse("https://www.postb.in/1780346657084-9427918170113").unwrap(),
            SubscriptionSecrets::new(
                PublicKey::from_sec1_bytes(&BASE64_URL_SAFE_NO_PAD.decode("BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8").unwrap()).unwrap(),
                AuthenticationSecret(BASE64_URL_SAFE_NO_PAD.decode("BTBZMqHH6r4Tts7J_aSIgg").unwrap()
                    .try_into().unwrap()),
            ),
            vec![subscription::Encoding::Aes128gcm],
        );
        let subscription = subscription.to_subscription();
        service.send(&subscription, String::from("Hello, world!").as_bytes()).await.unwrap();
    }
}