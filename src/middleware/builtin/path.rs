use crate::config::{AddPrefixConfig, ReplacePathConfig, ReplacePathRegexConfig, StripPrefixConfig, StripPrefixRegexConfig};
use regex::Regex;
use hyper::Uri;

/// StripPrefix middleware removes the specified prefixes from the request URL path
pub struct StripPrefixMiddleware {
    prefixes: Vec<String>,
    force_slash: bool,
}

impl StripPrefixMiddleware {
    pub fn new(config: StripPrefixConfig) -> Self {
        Self {
            prefixes: config.prefixes,
            force_slash: config.force_slash,
        }
    }

    /// Transform the URI by stripping the prefix
    /// Returns the new URI and optionally the original path for X-Forwarded-Prefix header
    pub fn transform_uri(&self, uri: &Uri) -> Option<(Uri, String)> {
        let path = uri.path();

        for prefix in &self.prefixes {
            if path.starts_with(prefix) {
                let original_prefix = prefix.clone();
                let mut new_path = path.strip_prefix(prefix).unwrap_or(path).to_string();

                // Ensure path starts with /
                if new_path.is_empty() || (!new_path.starts_with('/') && self.force_slash) {
                    new_path = format!("/{}", new_path);
                }
                if new_path.is_empty() {
                    new_path = "/".to_string();
                }

                // Rebuild URI with new path
                if let Some(new_uri) = rebuild_uri_with_path(uri, &new_path) {
                    return Some((new_uri, original_prefix));
                }
            }
        }

        None
    }
}

/// StripPrefixRegex middleware removes prefixes matching regex patterns
pub struct StripPrefixRegexMiddleware {
    patterns: Vec<Regex>,
}

impl StripPrefixRegexMiddleware {
    pub fn new(config: StripPrefixRegexConfig) -> Option<Self> {
        let patterns: Result<Vec<Regex>, _> = config
            .regex
            .iter()
            .map(|r| Regex::new(r))
            .collect();

        patterns.ok().map(|patterns| Self { patterns })
    }

    /// Transform the URI by stripping matched prefix
    pub fn transform_uri(&self, uri: &Uri) -> Option<(Uri, String)> {
        let path = uri.path();

        for pattern in &self.patterns {
            if let Some(mat) = pattern.find(path) {
                // Only match at the start of the path
                if mat.start() == 0 {
                    let matched = mat.as_str().to_string();
                    let mut new_path = path[mat.end()..].to_string();

                    // Ensure path starts with /
                    if new_path.is_empty() || !new_path.starts_with('/') {
                        new_path = format!("/{}", new_path);
                    }

                    if let Some(new_uri) = rebuild_uri_with_path(uri, &new_path) {
                        return Some((new_uri, matched));
                    }
                }
            }
        }

        None
    }
}

/// AddPrefix middleware adds a prefix to the request URL path
pub struct AddPrefixMiddleware {
    prefix: String,
}

impl AddPrefixMiddleware {
    pub fn new(config: AddPrefixConfig) -> Self {
        Self {
            prefix: config.prefix,
        }
    }

    /// Transform the URI by adding the prefix
    pub fn transform_uri(&self, uri: &Uri) -> Option<Uri> {
        let path = uri.path();
        let new_path = format!("{}{}", self.prefix, path);
        rebuild_uri_with_path(uri, &new_path)
    }
}

/// ReplacePath middleware replaces the entire request URL path
pub struct ReplacePathMiddleware {
    path: String,
}

impl ReplacePathMiddleware {
    pub fn new(config: ReplacePathConfig) -> Self {
        Self {
            path: config.path,
        }
    }

    /// Transform the URI by replacing the path
    /// Returns the new URI and the original path for X-Replaced-Path header
    pub fn transform_uri(&self, uri: &Uri) -> Option<(Uri, String)> {
        let original_path = uri.path().to_string();
        rebuild_uri_with_path(uri, &self.path).map(|u| (u, original_path))
    }
}

/// ReplacePathRegex middleware replaces the path using regex substitution
pub struct ReplacePathRegexMiddleware {
    pattern: Regex,
    replacement: String,
}

impl ReplacePathRegexMiddleware {
    pub fn new(config: ReplacePathRegexConfig) -> Option<Self> {
        Regex::new(&config.regex).ok().map(|pattern| Self {
            pattern,
            replacement: config.replacement,
        })
    }

    /// Transform the URI using regex replacement
    /// Returns the new URI and the original path
    pub fn transform_uri(&self, uri: &Uri) -> Option<(Uri, String)> {
        let path = uri.path();
        let original_path = path.to_string();
        let new_path = self.pattern.replace(path, &self.replacement).to_string();

        if new_path != original_path {
            rebuild_uri_with_path(uri, &new_path).map(|u| (u, original_path))
        } else {
            None
        }
    }
}

/// Helper to rebuild a URI with a new path while preserving query string
fn rebuild_uri_with_path(uri: &Uri, new_path: &str) -> Option<Uri> {
    let path_and_query = if let Some(query) = uri.query() {
        format!("{}?{}", new_path, query)
    } else {
        new_path.to_string()
    };

    let mut builder = Uri::builder();

    if let Some(scheme) = uri.scheme() {
        builder = builder.scheme(scheme.clone());
    }
    if let Some(authority) = uri.authority() {
        builder = builder.authority(authority.clone());
    }

    builder.path_and_query(path_and_query).build().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_prefix() {
        let config = StripPrefixConfig {
            prefixes: vec!["/api".to_string(), "/v1".to_string()],
            force_slash: true,
        };
        let middleware = StripPrefixMiddleware::new(config);

        let uri: Uri = "/api/users/123".parse().unwrap();
        let (new_uri, prefix) = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/users/123");
        assert_eq!(prefix, "/api");

        let uri: Uri = "/v1/items".parse().unwrap();
        let (new_uri, prefix) = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/items");
        assert_eq!(prefix, "/v1");

        // No match
        let uri: Uri = "/other/path".parse().unwrap();
        assert!(middleware.transform_uri(&uri).is_none());
    }

    #[test]
    fn test_strip_prefix_preserves_query() {
        let config = StripPrefixConfig {
            prefixes: vec!["/api".to_string()],
            force_slash: true,
        };
        let middleware = StripPrefixMiddleware::new(config);

        let uri: Uri = "/api/users?page=1&limit=10".parse().unwrap();
        let (new_uri, _) = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/users");
        assert_eq!(new_uri.query(), Some("page=1&limit=10"));
    }

    #[test]
    fn test_strip_prefix_empty_result() {
        let config = StripPrefixConfig {
            prefixes: vec!["/api".to_string()],
            force_slash: true,
        };
        let middleware = StripPrefixMiddleware::new(config);

        let uri: Uri = "/api".parse().unwrap();
        let (new_uri, _) = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/");
    }

    #[test]
    fn test_strip_prefix_regex() {
        let config = StripPrefixRegexConfig {
            regex: vec![r"^/api/v\d+".to_string()],
        };
        let middleware = StripPrefixRegexMiddleware::new(config).unwrap();

        let uri: Uri = "/api/v1/users".parse().unwrap();
        let (new_uri, matched) = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/users");
        assert_eq!(matched, "/api/v1");

        let uri: Uri = "/api/v2/items".parse().unwrap();
        let (new_uri, _) = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/items");
    }

    #[test]
    fn test_add_prefix() {
        let config = AddPrefixConfig {
            prefix: "/api/v1".to_string(),
        };
        let middleware = AddPrefixMiddleware::new(config);

        let uri: Uri = "/users/123".parse().unwrap();
        let new_uri = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/api/v1/users/123");
    }

    #[test]
    fn test_add_prefix_preserves_query() {
        let config = AddPrefixConfig {
            prefix: "/api".to_string(),
        };
        let middleware = AddPrefixMiddleware::new(config);

        let uri: Uri = "/users?id=1".parse().unwrap();
        let new_uri = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/api/users");
        assert_eq!(new_uri.query(), Some("id=1"));
    }

    #[test]
    fn test_replace_path() {
        let config = ReplacePathConfig {
            path: "/new/path".to_string(),
        };
        let middleware = ReplacePathMiddleware::new(config);

        let uri: Uri = "/old/path/here".parse().unwrap();
        let (new_uri, original) = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/new/path");
        assert_eq!(original, "/old/path/here");
    }

    #[test]
    fn test_replace_path_regex() {
        let config = ReplacePathRegexConfig {
            regex: r"^/api/(.*)".to_string(),
            replacement: "/v2/$1".to_string(),
        };
        let middleware = ReplacePathRegexMiddleware::new(config).unwrap();

        let uri: Uri = "/api/users/123".parse().unwrap();
        let (new_uri, original) = middleware.transform_uri(&uri).unwrap();
        assert_eq!(new_uri.path(), "/v2/users/123");
        assert_eq!(original, "/api/users/123");
    }

    #[test]
    fn test_replace_path_regex_no_match() {
        let config = ReplacePathRegexConfig {
            regex: r"^/api/(.*)".to_string(),
            replacement: "/v2/$1".to_string(),
        };
        let middleware = ReplacePathRegexMiddleware::new(config).unwrap();

        let uri: Uri = "/other/path".parse().unwrap();
        assert!(middleware.transform_uri(&uri).is_none());
    }
}
