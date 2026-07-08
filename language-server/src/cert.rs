use oid_registry::OidRegistry;
use sha2::{Digest, Sha256};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::X509Certificate;

pub struct PemBlock<'a> {
    pub label: &'a str,
    pub text: &'a str,
    pub start: usize,
    pub end: usize,
}

/// Scans `text` for `-----BEGIN X-----...-----END X-----` blocks and returns
/// the one containing byte offset `at`, if any.
pub fn find_pem_block_at(text: &str, at: usize) -> Option<PemBlock<'_>> {
    let mut search_from = 0;
    while let Some(begin_rel) = text[search_from..].find("-----BEGIN ") {
        let begin = search_from + begin_rel;
        let label_start = begin + "-----BEGIN ".len();
        let label_end = label_start + text[label_start..].find("-----")?;
        let label = &text[label_start..label_end];

        let footer = format!("-----END {label}-----");
        let footer_start = label_end + "-----".len();
        let footer_rel = text[footer_start..].find(&footer)?;
        let end = footer_start + footer_rel + footer.len();

        if at >= begin && at <= end {
            return Some(PemBlock {
                label,
                text: &text[begin..end],
                start: begin,
                end,
            });
        }

        search_from = end;
    }
    None
}

fn signature_algorithm_name(cert: &X509Certificate) -> String {
    let registry = OidRegistry::default().with_crypto().with_x509();
    match registry.get(&cert.signature_algorithm.algorithm) {
        Some(entry) => format!("{} (`{}`)", entry.sn(), cert.signature_algorithm.algorithm),
        None => format!("`{}`", cert.signature_algorithm.algorithm),
    }
}

fn format_general_name(name: &GeneralName) -> String {
    match name {
        GeneralName::DNSName(s) => format!("DNS:{s}"),
        GeneralName::IPAddress(ip) => format!("IP:{}", format_ip(ip)),
        GeneralName::RFC822Name(s) => format!("email:{s}"),
        GeneralName::URI(s) => format!("URI:{s}"),
        other => format!("{other:?}"),
    }
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("."),
        _ => bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

pub fn render_markdown(cert: &X509Certificate, der: &[u8]) -> String {
    let validity = cert.validity();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let seconds_left = validity.not_after.timestamp() - now;
    let days_left = seconds_left / 86_400;
    let expiry_note = if seconds_left < 0 {
        format!("**EXPIRED** {} days ago", -days_left)
    } else if days_left < 30 {
        format!("expires in **{days_left} days**")
    } else {
        format!("expires in {days_left} days")
    };

    let fingerprint = {
        let mut hasher = Sha256::new();
        hasher.update(der);
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    };

    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);

    let mut rows = vec![
        format!("| Subject | `{}` |", cert.subject()),
        format!("| Issuer | `{}` |", cert.issuer()),
        format!("| Serial | `{}` |", cert.raw_serial_as_string()),
        format!("| Valid from | {} |", validity.not_before),
        format!("| Valid to | {} ({expiry_note}) |", validity.not_after),
        format!(
            "| Signature algorithm | {} |",
            signature_algorithm_name(cert)
        ),
        format!("| CA | {} |", if is_ca { "yes" } else { "no" }),
        format!("| SHA-256 fingerprint | `{fingerprint}` |"),
    ];

    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                let names = san
                    .general_names
                    .iter()
                    .map(format_general_name)
                    .collect::<Vec<_>>()
                    .join(", ");
                rows.push(format!("| SANs | {names} |"));
            }
            ParsedExtension::KeyUsage(usage) => {
                rows.push(format!("| Key usage | {usage} |"));
            }
            _ => {}
        }
    }

    format!(
        "**X.509 Certificate**\n\n| Field | Value |\n|---|---|\n{}",
        rows.join("\n")
    )
}
