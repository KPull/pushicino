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

        let header = self.vapid.generate_authorization_header()?;
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
    FailedToPrepareRequest(subscription::Error),
    FailedToWritePem(p256::pkcs8::Error),
    InvalidEncodingKey(jsonwebtoken::errors::Error),
    FailedToGenerateToken(jsonwebtoken::errors::Error),
    InvalidHttpHeader(reqwest::header::InvalidHeaderValue),
    HttpRequestFailed(reqwest::Error),
}