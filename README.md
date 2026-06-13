This crate provides the tools necessary for your application to send Web Push messages
in accordance with [RFC 8030](https://datatracker.ietf.org/doc/html/rfc8030).

In addition to sending Push messages, this crate also handles:

* the generation of valid Voluntary Application Server Identification (VAPID) tokens,
  as required, in accordance with [RFC 8293](https://datatracker.ietf.org/doc/html/rfc8293) for any messages you send;
  and,
* the proper encryption of message content you send, using AES128GCM, in accordance with
  [RFC 8291](https://datatracker.ietf.org/doc/html/rfc8291).

The full documentation with examples is available on: https://docs.rs/pushicino.

## Quick Example
Creating a Push Server is as simple as:

```rust
use pushicino::{PushService, Vapid, Subject, VapidKey};

let service = PushService::new(Vapid::new(
  Subject::parse("mailto:vapid@yourapplication.com") ?,
  VapidKey::load_from_file("vapid.pem") ?,
));
```

Then, send the Push Service's public key to the frontend and collect push subscriptions from your user's browsers.
Use the Push Service to send arbitrary data directly to subscriptions using Web
Push. For example, you could collect a subscription and send a message using Axum, like so:

```rust
use std::sync::Arc;
use axum::http::StatusCode;
use axum::extract::State;
use axum::Json;
use serde::Serialize;
use pushicino::{PushService, Subscription};

struct ApplicationState {
  push_service: PushService,
}

async fn subscribe(
  State(application): State<Arc<ApplicationState>>,
  Json(request): Json<Subscription>,
) -> Result<(), StatusCode> {
  // At this point, you should persist the Subscription into a database or some other storage

  // Send a Web Push message immediately to the user, thanking them for subscribing!
  application.push_service.send(&request, "Hello, thanks for subscribing!".as_bytes())
          .await.unwrap();

  Ok(())
}

// Don't forget to register the `subscribe` handler with your Axum router!
```

A more comprehensive explanation and example can be found in the
[documentation](https://docs.rs/pushicino).

## Contributions

If you find this crate useful, we'd appreciate hearing feedback from you on how it can be improved. Additionally, feel
free to open pull requests or issues on GitHub.

AI disclosure: All code and documentation in this crate have been meticulously hand-crafted without using generative AI
agents. 
