use super::client::PendingChallenge;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

/// HTTP-01 ACME challenge handler
/// Responds to requests at /.well-known/acme-challenge/{token}
pub struct ChallengeHandler {
    pending: Arc<RwLock<HashMap<String, PendingChallenge>>>,
}

impl ChallengeHandler {
    pub fn new(pending: Arc<RwLock<HashMap<String, PendingChallenge>>>) -> Self {
        Self { pending }
    }

    /// Check if this request is an ACME challenge
    pub fn is_challenge_request<B>(req: &Request<B>) -> bool {
        req.uri()
            .path()
            .starts_with("/.well-known/acme-challenge/")
    }

    /// Handle an ACME challenge request
    pub async fn handle<B>(
        &self,
        req: &Request<B>,
    ) -> Option<Response<Full<Bytes>>> {
        let path = req.uri().path();

        if !path.starts_with("/.well-known/acme-challenge/") {
            return None;
        }

        let token = path.trim_start_matches("/.well-known/acme-challenge/");

        if token.is_empty() {
            return Some(not_found());
        }

        let challenges = self.pending.read().await;

        if let Some(challenge) = challenges.get(token) {
            debug!("Responding to ACME challenge for token: {}", token);

            let response = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from(challenge.key_authorization.clone())))
                .unwrap();

            Some(response)
        } else {
            debug!("Unknown ACME challenge token: {}", token);
            Some(not_found())
        }
    }
}

fn not_found() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("Not Found")))
        .unwrap()
}

/// Standalone function to check and handle ACME challenges
/// Returns Some(response) if this was a challenge request, None otherwise
pub async fn try_handle_challenge<B>(
    req: &Request<B>,
    pending: &Arc<RwLock<HashMap<String, PendingChallenge>>>,
) -> Option<Response<Full<Bytes>>> {
    if !ChallengeHandler::is_challenge_request(req) {
        return None;
    }

    let handler = ChallengeHandler::new(Arc::clone(pending));
    handler.handle(req).await
}
