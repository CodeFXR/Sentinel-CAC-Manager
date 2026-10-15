use pyo3::prelude::*;
use regex::Regex;
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::prelude::*;

#[pyclass]
#[derive(Clone, Debug)]
pub struct PyCardCertificate {
    #[pyo3(get)]
    pub id: String,
    #[pyo3(get)]
    pub label: String,
    #[pyo3(get)]
    pub subject: String,
    #[pyo3(get)]
    pub issuer: String,
    #[pyo3(get)]
    pub issuer_cn: String,
    #[pyo3(get)]
    pub cn: String,
    #[pyo3(get)]
    pub holder_name: String,
    #[pyo3(get)]
    pub edipi: String,
    #[pyo3(get)]
    pub valid_from_str: String,
    #[pyo3(get)]
    pub valid_to_str: String,
    #[pyo3(get)]
    pub serial: String,
    #[pyo3(get)]
    pub usage: String,
    #[pyo3(get)]
    pub is_valid: bool,
    #[pyo3(get)]
    pub status_text: String,
}

#[pymethods]
impl PyCardCertificate {
    fn __repr__(&self) -> String {
        format!(
            "<CardCertificate id='{}' label='{}' holder='{}' edipi='{}' valid={}>",
            self.id, self.label, self.holder_name, self.edipi, self.is_valid
        )
    }
}

pub fn parse_der_or_pem_bytes(
    id: String,
    label: String,
    usage: String,
    bytes: &[u8],
) -> Result<PyCardCertificate, String> {
    // If PEM formatted, extract DER bytes
    let der_data: Vec<u8> = if bytes.starts_with(b"-----BEGIN") || bytes.windows(27).any(|w| w == b"-----BEGIN CERTIFICATE-----") {
        match Pem::iter_from_buffer(bytes).next() {
            Some(Ok(pem)) => pem.contents,
            _ => return Err("Failed to decode PEM block".to_string()),
        }
    } else {
        bytes.to_vec()
    };

    let (_, x509) = parse_x509_certificate(&der_data)
        .map_err(|e| format!("ASN.1 X.509 DER parse error: {:?}", e))?;

    let subject = x509.subject().to_string();
    let issuer = x509.issuer().to_string();

    // Extract CN
    let cn = x509
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // Fallback regex
            let re_cn = Regex::new(r"CN\s*=\s*([^,\n]+)").unwrap();
            re_cn
                .captures(&subject)
                .map(|c| c[1].trim().to_string())
                .unwrap_or_default()
        });

    // Extract Issuer CN
    let issuer_cn = x509
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let re_cn = Regex::new(r"CN\s*=\s*([^,\n]+)").unwrap();
            re_cn
                .captures(&issuer)
                .map(|c| c[1].trim().to_string())
                .unwrap_or_else(|| issuer.clone())
        });

    // Extract DoD EDIPI & format Holder Name
    let mut holder_name = cn.clone();
    let mut edipi = String::new();

    if cn.contains('.') {
        let parts: Vec<&str> = cn.split('.').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
        if let Some(last_part) = parts.last() {
            if last_part.chars().all(|c| c.is_ascii_digit()) && last_part.len() >= 9 {
                edipi = last_part.to_string();
                let name_parts = &parts[..parts.len() - 1];
                if name_parts.len() >= 2 {
                    let last = name_parts[0];
                    let first_middle = name_parts[1..].join(" ");
                    holder_name = title_case(&format!("{} {}", first_middle, last));
                } else {
                    holder_name = title_case(&name_parts.join(" "));
                }
            }
        }
    }

    if edipi.is_empty() {
        let re_edipi = Regex::new(r"\b(\d{10})\b").unwrap();
        if let Some(caps) = re_edipi.captures(&subject) {
            edipi = caps[1].to_string();
        }
    }

    // Dates and validity
    let not_before = x509.validity().not_before;
    let not_after = x509.validity().not_after;

    let valid_from_str = format_asn1_time(&not_before);
    let valid_to_str = format_asn1_time(&not_after);

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let not_before_ts = not_before.timestamp();
    let not_after_ts = not_after.timestamp();

    let is_valid = now_ts >= not_before_ts && now_ts <= not_after_ts;
    let status_text = if now_ts > not_after_ts {
        "Expired".to_string()
    } else {
        let remaining_days = (not_after_ts - now_ts) / 86400;
        if remaining_days < 60 {
            format!("Expiring soon ({} days)", remaining_days)
        } else {
            format!("Valid through {}", valid_to_str)
        }
    };

    let serial = x509.raw_serial_as_string();

    Ok(PyCardCertificate {
        id,
        label,
        subject,
        issuer,
        issuer_cn,
        cn,
        holder_name,
        edipi,
        valid_from_str,
        valid_to_str,
        serial,
        usage,
        is_valid,
        status_text,
    })
}

fn title_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = true;

    for c in s.chars() {
        if c.is_whitespace() || c == '.' || c == '-' {
            result.push(c);
            capitalize_next = true;
        } else if capitalize_next {
            result.extend(c.to_uppercase());
            capitalize_next = false;
        } else {
            result.extend(c.to_lowercase());
        }
    }
    result
}

fn format_asn1_time(time: &ASN1Time) -> String {
    time.to_rfc2822().unwrap_or_else(|_| time.to_string())
}
