use crate::config::CompressConfig;
use flate2::write::GzEncoder;
use flate2::Compression;
use hyper::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE};
use hyper::HeaderMap;
use std::io::Write;

/// Compression middleware for response body compression
pub struct CompressMiddleware {
    min_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CompressionAlgorithm {
    Gzip,
    Brotli,
    None,
}

impl CompressMiddleware {
    pub fn new(config: CompressConfig) -> Self {
        Self {
            min_size: config.min_response_body_bytes,
        }
    }

    /// Determine best compression algorithm from Accept-Encoding header
    #[inline]
    pub fn select_algorithm(headers: &HeaderMap) -> CompressionAlgorithm {
        let accept = match headers.get(ACCEPT_ENCODING) {
            Some(v) => match v.to_str() {
                Ok(s) => s.to_lowercase(),
                Err(_) => return CompressionAlgorithm::None,
            },
            None => return CompressionAlgorithm::None,
        };

        // Prefer brotli over gzip
        if accept.contains("br") {
            return CompressionAlgorithm::Brotli;
        }
        if accept.contains("gzip") {
            return CompressionAlgorithm::Gzip;
        }

        CompressionAlgorithm::None
    }

    /// Check if content type should be compressed
    #[inline]
    pub fn should_compress_content_type(headers: &HeaderMap) -> bool {
        let content_type = match headers.get(CONTENT_TYPE) {
            Some(v) => match v.to_str() {
                Ok(s) => s.to_lowercase(),
                Err(_) => return false,
            },
            None => return true, // Assume compressible if no content type
        };

        // Compress text-based content types
        content_type.contains("text/")
            || content_type.contains("application/json")
            || content_type.contains("application/xml")
            || content_type.contains("application/javascript")
            || content_type.contains("application/xhtml")
            || content_type.contains("image/svg")
    }

    /// Check if response is already compressed
    #[inline]
    pub fn is_already_compressed(headers: &HeaderMap) -> bool {
        headers.contains_key(CONTENT_ENCODING)
    }

    /// Check if body size meets minimum threshold
    #[inline]
    pub fn meets_size_threshold(&self, size: Option<u64>) -> bool {
        match size {
            Some(s) => s >= self.min_size,
            None => true, // Compress if size unknown (streaming)
        }
    }

    /// Compress bytes with gzip
    pub fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(data)?;
        encoder.finish()
    }

    /// Compress bytes with brotli
    pub fn compress_brotli(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let mut output = Vec::new();
        let mut writer = brotli::CompressorWriter::new(&mut output, 4096, 4, 22);
        writer.write_all(data)?;
        drop(writer);
        Ok(output)
    }

    /// Compress data with the specified algorithm
    pub fn compress(data: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>, std::io::Error> {
        match algorithm {
            CompressionAlgorithm::Gzip => Self::compress_gzip(data),
            CompressionAlgorithm::Brotli => Self::compress_brotli(data),
            CompressionAlgorithm::None => Ok(data.to_vec()),
        }
    }

    /// Get the Content-Encoding header value for an algorithm
    #[inline]
    pub fn encoding_header(algorithm: CompressionAlgorithm) -> Option<&'static str> {
        match algorithm {
            CompressionAlgorithm::Gzip => Some("gzip"),
            CompressionAlgorithm::Brotli => Some("br"),
            CompressionAlgorithm::None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn test_select_algorithm_gzip() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, deflate"));
        assert_eq!(
            CompressMiddleware::select_algorithm(&headers),
            CompressionAlgorithm::Gzip
        );
    }

    #[test]
    fn test_select_algorithm_brotli() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, br"));
        assert_eq!(
            CompressMiddleware::select_algorithm(&headers),
            CompressionAlgorithm::Brotli
        );
    }

    #[test]
    fn test_select_algorithm_none() {
        let headers = HeaderMap::new();
        assert_eq!(
            CompressMiddleware::select_algorithm(&headers),
            CompressionAlgorithm::None
        );
    }

    #[test]
    fn test_compress_gzip() {
        // Need larger data for gzip to actually compress (small data has overhead)
        let data = "Hello, World! This is some test data that should compress well. ".repeat(100);
        let compressed = CompressMiddleware::compress_gzip(data.as_bytes()).unwrap();
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_compress_brotli() {
        let data = "Hello, World! This is some test data that should compress well. ".repeat(100);
        let compressed = CompressMiddleware::compress_brotli(data.as_bytes()).unwrap();
        assert!(compressed.len() < data.len());
    }

    #[test]
    fn test_should_compress_content_type() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        assert!(CompressMiddleware::should_compress_content_type(&headers));

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert!(CompressMiddleware::should_compress_content_type(&headers));

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("image/png"));
        assert!(!CompressMiddleware::should_compress_content_type(&headers));
    }
}
