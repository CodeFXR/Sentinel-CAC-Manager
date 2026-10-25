//! Native RFC 6960 OCSP URL Policy Validator, AIA Extractor, and Responder Verifier.
//!
//! Enforces strict `.mil` domain boundaries on OCSP responder URIs (with explicit test override),
//! extracts Authority Information Access (AIA) OCSP URIs directly from ASN.1 DER certificates via
//! `x509-parser`, and verifies delegated OCSP responder validity windows and `id-kp-OCSPSigning`
//! (`1.3.6.1.5.5.7.3.9`) ExtendedKeyUsage authorization.

use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

/// OID for `id-ad-ocsp` (`1.3.6.1.5.5.7.48.1`) in Authority Information Access.
pub const OID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";

/// Validate an OCSP responder URL against scheme, injection, and `.mil` domain boundaries.
pub fn validate_ocsp_url_rust(url: &str, allow_non_mil: bool) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed.len() > 512 {
        return false;
    }

    if trimmed
        .chars()
        .any(|c| (c as u32) < 0x20 || (c as u32) == 0x7f || c.is_whitespace())
    {
        return false;
    }

    let rest = if let Some(r) = trimmed.strip_prefix("http://") {
        r
    } else if let Some(r) = trimmed.strip_prefix("https://") {
        r
    } else {
        return false;
    };

    let authority_end = rest.find(&['/', '?', '#'][..]).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return false;
    }

    // Strip optional :port
    let host = if authority.starts_with('[') {
        // IPv6 literal is never a .mil DNS name
        if !allow_non_mil {
            return false;
        }
        authority
    } else {
        match authority.rfind(':') {
            Some(colon_idx) => {
                let port_str = &authority[colon_idx + 1..];
                if port_str.is_empty() || !port_str.chars().all(|c| c.is_ascii_digit()) {
                    return false;
                }
                &authority[..colon_idx]
            }
            None => authority,
        }
    };

    let host_clean = host.trim_end_matches('.').to_ascii_lowercase();
    if host_clean.is_empty() {
        return false;
    }

    if !host_clean
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return false;
    }

    if allow_non_mil {
        return true;
    }

    host_clean == "mil" || host_clean.ends_with(".mil")
}

/// Extract and validate all OCSP responder URIs from an X.509 DER certificate's AIA extension.
pub fn extract_ocsp_urls_from_der_rust(der_bytes: &[u8], allow_non_mil: bool) -> Vec<String> {
    let mut urls = Vec::new();
    let Ok((_, cert)) = parse_x509_certificate(der_bytes) else {
        return urls;
    };

    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in &aia.accessdescs {
                if desc.access_method.to_id_string() == OID_AD_OCSP {
                    if let GeneralName::URI(uri) = desc.access_location {
                        let candidate = uri.trim().to_string();
                        if validate_ocsp_url_rust(&candidate, allow_non_mil)
                            && !urls.contains(&candidate)
                        {
                            urls.push(candidate);
                        }
                    }
                }
            }
        }
    }

    urls
}

/// Inspect an OCSP responder certificate (`responder_der`) against its `issuer_der` for:
/// 1. Current validity window (`not_before <= now <= not_after`)
/// 2. RFC 6960 Section 4.2.2.2 responder authorization (either direct issuer match, or issued by
///    `issuer_der` with `ExtendedKeyUsage` containing `id-kp-OCSPSigning` `1.3.6.1.5.5.7.3.9`).
///
/// Returns `(is_within_validity_window, is_authorized_responder, diagnostic_message)`.
pub fn verify_ocsp_responder_cert_der_rust(
    responder_der: &[u8],
    issuer_der: &[u8],
) -> (bool, bool, String) {
    let Ok((_, resp_cert)) = parse_x509_certificate(responder_der) else {
        return (
            false,
            false,
            "Failed to parse OCSP responder ASN.1 DER certificate".to_string(),
        );
    };
    let Ok((_, iss_cert)) = parse_x509_certificate(issuer_der) else {
        return (
            false,
            false,
            "Failed to parse issuer ASN.1 DER certificate".to_string(),
        );
    };

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let not_before_ts = resp_cert.validity().not_before.timestamp();
    let not_after_ts = resp_cert.validity().not_after.timestamp();

    let is_valid_time = now_ts > 0 && now_ts >= not_before_ts && now_ts <= not_after_ts;
    if !is_valid_time {
        return (
            false,
            false,
            "OCSP responder certificate is expired or not yet valid".to_string(),
        );
    }

    // Case 1: Responder certificate is the exact issuer certificate
    if responder_der == issuer_der {
        return (
            true,
            true,
            "Direct issuer OCSP responder verified".to_string(),
        );
    }

    // Case 2: Delegated OCSP responder issued by the CA with id-kp-OCSPSigning EKU
    if resp_cert.issuer() != iss_cert.subject() {
        return (
            true,
            false,
            "Delegated OCSP responder issuer DN does not match certificate issuer subject DN"
                .to_string(),
        );
    }

    let mut has_ocsp_signing_eku = false;
    for ext in resp_cert.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
            if eku.ocsp_signing {
                has_ocsp_signing_eku = true;
                break;
            }
            for oid in &eku.other {
                if oid.to_id_string() == "1.3.6.1.5.5.7.3.9" {
                    has_ocsp_signing_eku = true;
                    break;
                }
            }
        }
    }

    if !has_ocsp_signing_eku {
        return (
            true,
            false,
            "Delegated OCSP responder lacks ExtendedKeyUsage id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9)"
                .to_string(),
        );
    }

    (
        true,
        true,
        "Authorized delegated OCSP responder (id-kp-OCSPSigning) verified".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ocsp_url_mil_boundary() {
        assert!(validate_ocsp_url_rust("http://ocsp.disa.mil", false));
        assert!(validate_ocsp_url_rust("https://ocsp.nsn0.rcvs.nit.disa.mil/ocsp", false));
        assert!(validate_ocsp_url_rust("http://ocsp.disa.mil:80/status", false));
        assert!(!validate_ocsp_url_rust("http://ocsp.evil.com", false));
        assert!(!validate_ocsp_url_rust("http://mil.evil.com", false));
        assert!(!validate_ocsp_url_rust("ftp://ocsp.disa.mil", false));
        assert!(!validate_ocsp_url_rust("http://user:pass@ocsp.disa.mil", false));
        assert!(validate_ocsp_url_rust("http://127.0.0.1:8888/ocsp", true));
    }
}
