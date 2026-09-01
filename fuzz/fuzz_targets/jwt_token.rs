#![no_main]

use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::LazyLock;
use trafficcop::config::JwtConfig;
use trafficcop::middleware::builtin::JwtMiddleware;

static MIDDLEWARE: LazyLock<JwtMiddleware> = LazyLock::new(|| {
    JwtMiddleware::new(JwtConfig {
        secret: Some("fuzz-secret".to_string()),
        public_key: None,
        algorithm: "HS256".to_string(),
        issuer: None,
        audience: None,
        header_name: "Authorization".to_string(),
        header_prefix: "Bearer ".to_string(),
        query_param: None,
        cookie_name: None,
        forward_claims: HashMap::new(),
        strip_authorization_header: false,
    })
    .expect("valid fuzz config")
});

// JWT tokens are fully attacker-controlled input on authenticated routes.
// Validation must never panic regardless of token contents.
fuzz_target!(|data: &[u8]| {
    if let Ok(token) = std::str::from_utf8(data) {
        if let Ok(header_value) = hyper::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            let req = hyper::Request::builder()
                .header(hyper::header::AUTHORIZATION, header_value)
                .body(())
                .unwrap();
            let _ = MIDDLEWARE.validate(&req);
        }
    }
});
