//! Request path normalization, matching Traefik/Go semantics:
//! routing sees the percent-decoded path, and with `sanitizePath` (default
//! true) dot-segments and duplicate slashes are removed before routing, so
//! `/%61dmin`, `/a/../admin` and `//admin` cannot dodge a `/admin` router.

use std::borrow::Cow;

/// Percent-decode a path (Go `url.PathUnescape` semantics: invalid escapes
/// are kept literally).
pub fn decode(path: &str) -> Cow<'_, str> {
    if !path.contains('%') {
        return Cow::Borrowed(path);
    }
    Cow::Owned(String::from_utf8_lossy(&decode_bytes(path)).into_owned())
}

fn decode_bytes(path: &str) -> Vec<u8> {
    let b = path.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h << 4 | l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Sanitized, canonically re-encoded path, or `None` if already canonical.
/// Decodes, applies `path.Clean` (keeping a trailing slash), and re-encodes
/// only bytes that must be escaped in a path.
pub fn sanitize(raw: &str) -> Option<String> {
    let decoded = decode_bytes(raw);
    let trailing = decoded.last() == Some(&b'/') && decoded.len() > 1;

    let mut stack: Vec<&[u8]> = Vec::new();
    for seg in decoded.split(|c| *c == b'/') {
        match seg {
            b"" | b"." => {}
            b".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }

    let mut out = String::with_capacity(raw.len());
    for seg in &stack {
        out.push('/');
        encode_segment(seg, &mut out);
    }
    if out.is_empty() || trailing {
        out.push('/');
    }
    (out != raw).then_some(out)
}

/// Escape everything outside RFC 3986 pchar (minus '/', which separates).
fn encode_segment(seg: &[u8], out: &mut String) {
    for &c in seg {
        let keep = c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
            );
        if keep {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_matches_go() {
        assert_eq!(decode("/%61dmin"), "/admin");
        assert_eq!(decode("/a%2Fb"), "/a/b");
        assert_eq!(decode("/100%"), "/100%");
        assert_eq!(decode("/x%zz"), "/x%zz");
        assert_eq!(decode("/plain"), "/plain");
    }

    #[test]
    fn sanitize_bypass_forms() {
        assert_eq!(sanitize("/%61dmin").as_deref(), Some("/admin"));
        assert_eq!(sanitize("/public/../admin").as_deref(), Some("/admin"));
        assert_eq!(sanitize("/public%2F..%2Fadmin").as_deref(), Some("/admin"));
        assert_eq!(sanitize("//admin").as_deref(), Some("/admin"));
        assert_eq!(sanitize("/./admin/").as_deref(), Some("/admin/"));
        assert_eq!(sanitize("/../../etc").as_deref(), Some("/etc"));
        assert_eq!(sanitize("").as_deref(), Some("/"));
    }

    #[test]
    fn canonical_paths_untouched() {
        for p in ["/", "/admin", "/admin/", "/a/b:c@d", "/sp%20ace", "/pct%25"] {
            assert_eq!(sanitize(p), None, "{p}");
        }
        // lowercase escapes are canonicalized to uppercase
        assert_eq!(sanitize("/sp%2aace").as_deref(), Some("/sp*ace"));
        assert_eq!(sanitize("/a b").as_deref(), Some("/a%20b"));
    }
}
