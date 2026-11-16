//! Traefik v3 TCP rule language:
//! `HostSNI`, `HostSNIRegexp`, `ClientIP`, `ALPN`, combined with `&&`, `||`,
//! `!` and parentheses. Parsing is strict: anything not understood is an
//! error, never a catch-all.

use crate::middleware::source::parse_net;
use ipnetwork::IpNetwork;
use regex::Regex;
use std::net::IpAddr;

/// Parsed TCP rule.
#[derive(Clone, Debug)]
pub enum TcpRule {
    /// `HostSNI(`*`)`: matches every connection, TLS or not.
    Any,
    /// `HostSNI(`a`)`: TLS SNI equals one of the names (`*.x` wildcards allowed).
    HostSni(Vec<String>),
    /// `HostSNIRegexp(`re`)`.
    HostSniRegexp(Regex),
    /// `ClientIP(`cidr`)`.
    ClientIp(Vec<IpNetwork>),
    /// `ALPN(`proto`)`: one of the offered ALPN protocols.
    Alpn(Vec<String>),
    /// Conjunction.
    And(Box<TcpRule>, Box<TcpRule>),
    /// Disjunction.
    Or(Box<TcpRule>, Box<TcpRule>),
    /// Negation.
    Not(Box<TcpRule>),
}

/// Facts about a connection available before proxying.
pub struct ConnInfo<'a> {
    /// TLS SNI, if the client sent a ClientHello with one.
    pub sni: Option<&'a str>,
    /// ALPN protocols offered in the ClientHello.
    pub alpn: &'a [String],
    /// Client IP.
    pub client_ip: Option<IpAddr>,
}

impl TcpRule {
    /// Parse a rule string. `*` is accepted as an alias of `HostSNI(`*`)`.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input == "*" {
            return Ok(TcpRule::Any);
        }
        let tokens = tokenize(input)?;
        let mut p = Parser { tokens, pos: 0 };
        let rule = p.or()?;
        if p.pos != p.tokens.len() {
            return Err(format!("unexpected trailing input in TCP rule '{input}'"));
        }
        Ok(rule)
    }

    /// Whether the connection matches.
    pub fn matches(&self, c: &ConnInfo<'_>) -> bool {
        match self {
            TcpRule::Any => true,
            TcpRule::HostSni(hosts) => c.sni.is_some_and(|sni| {
                let sni = sni.trim_end_matches('.');
                hosts.iter().any(|h| match h.strip_prefix("*.") {
                    Some(suffix) => sni.len().checked_sub(suffix.len() + 1).is_some_and(|i| {
                        sni.as_bytes()[i] == b'.' && sni[i + 1..].eq_ignore_ascii_case(suffix)
                    }),
                    None => h.eq_ignore_ascii_case(sni),
                })
            }),
            TcpRule::HostSniRegexp(re) => c.sni.is_some_and(|s| re.is_match(s)),
            TcpRule::ClientIp(nets) => c
                .client_ip
                .is_some_and(|ip| nets.iter().any(|n| n.contains(ip))),
            TcpRule::Alpn(protos) => c.alpn.iter().any(|a| protos.contains(a)),
            TcpRule::And(a, b) => a.matches(c) && b.matches(c),
            TcpRule::Or(a, b) => a.matches(c) || b.matches(c),
            TcpRule::Not(a) => !a.matches(c),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    LParen,
    RParen,
    Comma,
    And,
    Or,
    Not,
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let mut out = Vec::new();
    let mut chars = s.char_indices().peekable();
    while let Some(&(i, c)) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                out.push(Tok::LParen);
                chars.next();
            }
            ')' => {
                out.push(Tok::RParen);
                chars.next();
            }
            ',' => {
                out.push(Tok::Comma);
                chars.next();
            }
            '!' => {
                out.push(Tok::Not);
                chars.next();
            }
            '&' | '|' => {
                chars.next();
                match chars.next() {
                    Some((_, n)) if n == c => out.push(if c == '&' { Tok::And } else { Tok::Or }),
                    _ => return Err(format!("expected '{c}{c}' at offset {i}")),
                }
            }
            '`' | '"' => {
                chars.next();
                let mut v = String::new();
                loop {
                    match chars.next() {
                        Some((_, ch)) if ch == c => break,
                        Some((_, ch)) => v.push(ch),
                        None => return Err("unterminated string in TCP rule".to_string()),
                    }
                }
                out.push(Tok::Str(v));
            }
            c if c.is_ascii_alphabetic() => {
                let mut v = String::new();
                while let Some(&(_, ch)) = chars.peek() {
                    if ch.is_ascii_alphanumeric() {
                        v.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                out.push(Tok::Ident(v));
            }
            other => return Err(format!("unexpected character '{other}' in TCP rule")),
        }
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn expect(&mut self, t: Tok) -> Result<(), String> {
        match self.next() {
            Some(ref got) if *got == t => Ok(()),
            got => Err(format!("expected {t:?}, found {got:?}")),
        }
    }

    fn or(&mut self) -> Result<TcpRule, String> {
        let mut left = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.pos += 1;
            left = TcpRule::Or(Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<TcpRule, String> {
        let mut left = self.unary()?;
        while self.peek() == Some(&Tok::And) {
            self.pos += 1;
            left = TcpRule::And(Box::new(left), Box::new(self.unary()?));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<TcpRule, String> {
        match self.next() {
            Some(Tok::Not) => Ok(TcpRule::Not(Box::new(self.unary()?))),
            Some(Tok::LParen) => {
                let r = self.or()?;
                self.expect(Tok::RParen)?;
                Ok(r)
            }
            Some(Tok::Ident(name)) => self.call(&name),
            other => Err(format!("unexpected token {other:?} in TCP rule")),
        }
    }

    fn call(&mut self, name: &str) -> Result<TcpRule, String> {
        self.expect(Tok::LParen)?;
        let mut args = Vec::new();
        loop {
            match self.next() {
                Some(Tok::Str(s)) => args.push(s),
                other => {
                    return Err(format!(
                        "{name}: expected a quoted argument, found {other:?}"
                    ));
                }
            }
            match self.next() {
                Some(Tok::Comma) => continue,
                Some(Tok::RParen) => break,
                other => return Err(format!("{name}: expected ',' or ')', found {other:?}")),
            }
        }
        if args.iter().any(|a| a.is_empty()) {
            return Err(format!("{name}: empty argument"));
        }
        match name {
            "HostSNI" => {
                if args.iter().any(|a| a == "*") {
                    if args.len() > 1 {
                        return Err("HostSNI(`*`) cannot be combined with other names".into());
                    }
                    return Ok(TcpRule::Any);
                }
                Ok(TcpRule::HostSni(args))
            }
            "HostSNIRegexp" => {
                if args.len() != 1 {
                    return Err("HostSNIRegexp takes exactly one argument".into());
                }
                Regex::new(&format!("(?i){}", args[0]))
                    .map(TcpRule::HostSniRegexp)
                    .map_err(|e| format!("HostSNIRegexp: {e}"))
            }
            "ClientIP" => args
                .iter()
                .map(|a| parse_net(a))
                .collect::<Result<Vec<_>, _>>()
                .map(TcpRule::ClientIp)
                .map_err(|e| format!("ClientIP: {e}")),
            "ALPN" => {
                if args.iter().any(|a| a.eq_ignore_ascii_case("acme-tls/1")) {
                    return Err("ALPN(`acme-tls/1`) is reserved".into());
                }
                Ok(TcpRule::Alpn(args))
            }
            other => Err(format!("unknown TCP matcher '{other}'")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn<'a>(sni: Option<&'a str>, alpn: &'a [String], ip: &str) -> ConnInfo<'a> {
        ConnInfo {
            sni,
            alpn,
            client_ip: Some(ip.parse().unwrap()),
        }
    }

    #[test]
    fn compound_rules_are_evaluated_not_catch_all() {
        let r = TcpRule::parse("ClientIP(`10.0.0.0/8`) && HostSNI(`*`)").unwrap();
        assert!(r.matches(&conn(None, &[], "10.1.2.3")));
        assert!(!r.matches(&conn(None, &[], "8.8.8.8")));
        assert!(!r.matches(&conn(Some("x.com"), &[], "8.8.8.8")));

        let r = TcpRule::parse("HostSNI(`x.com`) || HostSNI(`y.com`)").unwrap();
        assert!(r.matches(&conn(Some("x.com"), &[], "1.1.1.1")));
        assert!(r.matches(&conn(Some("Y.COM"), &[], "1.1.1.1")));
        assert!(!r.matches(&conn(Some("z.com"), &[], "1.1.1.1")));
        assert!(!r.matches(&conn(None, &[], "1.1.1.1")));
    }

    #[test]
    fn not_parens_regexp_alpn() {
        let r = TcpRule::parse("!(ClientIP(`192.168.0.0/16`)) && (HostSNIRegexp(`^db-[0-9]+\\.internal$`) || ALPN(`h2`))").unwrap();
        let h2 = vec!["h2".to_string()];
        assert!(r.matches(&conn(Some("db-1.internal"), &[], "1.1.1.1")));
        assert!(r.matches(&conn(Some("other"), &h2, "1.1.1.1")));
        assert!(!r.matches(&conn(Some("db-1.internal"), &[], "192.168.1.1")));
    }

    #[test]
    fn wildcard_hostsni() {
        let r = TcpRule::parse("HostSNI(`*.example.com`)").unwrap();
        assert!(r.matches(&conn(Some("a.example.com"), &[], "1.1.1.1")));
        assert!(!r.matches(&conn(Some("example.com"), &[], "1.1.1.1")));
        assert!(!r.matches(&conn(Some("evilexample.com"), &[], "1.1.1.1")));
    }

    #[test]
    fn parse_errors_are_errors() {
        for bad in [
            "",
            "HostSNI(`a`",
            "HostSNI(a)",
            "Host(`a`)",
            "ClientIP(`10.0.0.0/33`)",
            "HostSNI(`a`) & HostSNI(`b`)",
            "HostSNI(`a`) HostSNI(`b`)",
            "HostSNIRegexp(`(`)",
            "HostSNI(`*`, `a`)",
            "ALPN(`acme-tls/1`)",
        ] {
            assert!(TcpRule::parse(bad).is_err(), "{bad:?} should fail");
        }
        assert!(matches!(TcpRule::parse("*").unwrap(), TcpRule::Any));
        assert!(matches!(
            TcpRule::parse("HostSNI(`*`)").unwrap(),
            TcpRule::Any
        ));
    }
}
