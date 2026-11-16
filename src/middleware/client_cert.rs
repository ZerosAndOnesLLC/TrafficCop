//! Client-certificate header formatting for passTLSClientCert, following
//! Traefik's `X-Forwarded-Tls-Client-Cert` / `-Info` formats.

use crate::config::TlsClientCertInfo;
use base64::Engine;
use rustls::pki_types::CertificateDer;
use x509_parser::oid_registry::{OID_DOMAIN_COMPONENT, OID_X509_SERIALNUMBER};
use x509_parser::prelude::*;

/// Base64 DER of each certificate (PEM without armor/newlines), comma-separated.
pub fn format_pem(certs: &[CertificateDer<'_>]) -> String {
    certs
        .iter()
        .map(|c| base64::engine::general_purpose::STANDARD.encode(c.as_ref()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Selected certificate fields, query-escaped. `None` if no certificate parses.
pub fn format_info(certs: &[CertificateDer<'_>], info: &TlsClientCertInfo) -> Option<String> {
    let mut per_cert = Vec::new();
    for der in certs {
        let (_, cert) = X509Certificate::from_der(der.as_ref()).ok()?;
        let mut values = Vec::new();

        if let Some(s) = &info.subject {
            let dn = dn_info(
                cert.subject(),
                [
                    s.country,
                    s.province,
                    s.locality,
                    s.organization,
                    s.organizational_unit,
                    s.common_name,
                    s.serial_number,
                    s.domain_component,
                ],
            );
            if !dn.is_empty() {
                values.push(format!("Subject=\"{dn}\""));
            }
        }
        if let Some(i) = &info.issuer {
            let dn = dn_info(
                cert.issuer(),
                [
                    i.country,
                    i.province,
                    i.locality,
                    i.organization,
                    false,
                    i.common_name,
                    i.serial_number,
                    i.domain_component,
                ],
            );
            if !dn.is_empty() {
                values.push(format!("Issuer=\"{dn}\""));
            }
        }
        if info.serial_number {
            values.push(format!("SerialNumber=\"{}\"", cert.serial));
        }
        if info.not_before {
            values.push(format!("NB=\"{}\"", cert.validity().not_before.timestamp()));
        }
        if info.not_after {
            values.push(format!("NA=\"{}\"", cert.validity().not_after.timestamp()));
        }
        if info.sans {
            let sans = sans(&cert);
            if !sans.is_empty() {
                values.push(format!("SAN=\"{}\"", sans.join(",")));
            }
        }
        per_cert.push(values.join(";"));
    }
    Some(query_escape(&per_cert.join(",")))
}

/// Flags in Traefik order: C, ST, L, O, OU, CN, SerialNumber, DC.
fn dn_info(name: &X509Name<'_>, flags: [bool; 8]) -> String {
    let collect = |it: &mut dyn Iterator<Item = &AttributeTypeAndValue<'_>>| -> Vec<String> {
        it.filter_map(|a| a.as_str().ok().map(str::to_string))
            .collect()
    };
    let fields: [(&str, Vec<String>); 8] = [
        ("C", collect(&mut name.iter_country())),
        ("ST", collect(&mut name.iter_state_or_province())),
        ("L", collect(&mut name.iter_locality())),
        ("O", collect(&mut name.iter_organization())),
        ("OU", collect(&mut name.iter_organizational_unit())),
        ("CN", collect(&mut name.iter_common_name())),
        (
            "SerialNumber",
            collect(&mut name.iter_by_oid(&OID_X509_SERIALNUMBER)),
        ),
        ("DC", collect(&mut name.iter_by_oid(&OID_DOMAIN_COMPONENT))),
    ];
    fields
        .iter()
        .zip(flags)
        .filter(|(_, on)| *on)
        .flat_map(|((prefix, vals), _)| vals.iter().map(move |v| format!("{prefix}={v}")))
        .collect::<Vec<_>>()
        .join(",")
}

fn sans(cert: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(ext)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    let (mut dns, mut email, mut ip, mut uri) = (vec![], vec![], vec![], vec![]);
    for n in &ext.value.general_names {
        match n {
            GeneralName::DNSName(d) => dns.push(d.to_string()),
            GeneralName::RFC822Name(e) => email.push(e.to_string()),
            GeneralName::IPAddress(b) => match b.len() {
                4 => ip.push(
                    std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*b).unwrap_or_default())
                        .to_string(),
                ),
                16 => ip.push(
                    std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*b).unwrap_or_default())
                        .to_string(),
                ),
                _ => {}
            },
            GeneralName::URI(u) => uri.push(u.to_string()),
            _ => {}
        }
    }
    [dns, email, ip, uri].concat()
}

/// Go `url.QueryEscape`: unreserved `A-Za-z0-9-_.~` kept, space -> `+`, rest `%XX`.
fn query_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_escape_matches_go() {
        assert_eq!(
            query_escape("Subject=\"CN=a b\";x~*"),
            "Subject%3D%22CN%3Da+b%22%3Bx~%2A"
        );
    }

    #[test]
    fn pem_is_base64_der_joined() {
        let a = CertificateDer::from(vec![1u8, 2, 3]);
        let b = CertificateDer::from(vec![4u8]);
        assert_eq!(format_pem(&[a, b]), "AQID,BA==");
    }
}
