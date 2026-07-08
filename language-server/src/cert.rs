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

pub fn is_certificate_label(label: &str) -> bool {
    matches!(
        label,
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE"
    )
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

fn oid_registry() -> OidRegistry<'static> {
    OidRegistry::default().with_crypto().with_x509()
}

fn signature_algorithm_name(cert: &X509Certificate, registry: &OidRegistry) -> String {
    match registry.get(&cert.signature_algorithm.algorithm) {
        Some(entry) => format!("{} (`{}`)", entry.sn(), cert.signature_algorithm.algorithm),
        None => format!("`{}`", cert.signature_algorithm.algorithm),
    }
}

fn extension_name(oid: &x509_parser::der_parser::Oid, registry: &OidRegistry) -> String {
    match registry.get(oid) {
        Some(entry) => entry.sn().to_string(),
        None => oid.to_string(),
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

fn format_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
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

fn fingerprint_sha256(der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(der);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn expiry_note(cert: &X509Certificate) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let seconds_left = cert.validity().not_after.timestamp() - now;
    let days_left = seconds_left / 86_400;
    if seconds_left < 0 {
        format!("**EXPIRED** {} days ago", -days_left)
    } else if days_left < 30 {
        format!("expires in **{days_left} days**")
    } else {
        format!("expires in {days_left} days")
    }
}

/// The fields shown in both the concise hover popup and the full file dump.
fn summary_rows(cert: &X509Certificate, der: &[u8], registry: &OidRegistry) -> Vec<String> {
    let validity = cert.validity();
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);

    vec![
        format!("| Subject | `{}` |", cert.subject()),
        format!("| Issuer | `{}` |", cert.issuer()),
        format!("| Serial | `{}` |", cert.raw_serial_as_string()),
        format!("| Valid from | {} |", validity.not_before),
        format!(
            "| Valid to | {} ({}) |",
            validity.not_after,
            expiry_note(cert)
        ),
        format!(
            "| Signature algorithm | {} |",
            signature_algorithm_name(cert, registry)
        ),
        format!("| CA | {} |", if is_ca { "yes" } else { "no" }),
        format!("| SHA-256 fingerprint | `{}` |", fingerprint_sha256(der)),
    ]
}

/// Concise summary for the hover tooltip: identity, validity, and only the
/// two extensions people usually care about at a glance.
pub fn render_markdown(cert: &X509Certificate, der: &[u8]) -> String {
    let registry = oid_registry();
    let mut rows = summary_rows(cert, der, &registry);

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

/// Full dump written to the `.decoded.md` file: the summary table plus every
/// extension the certificate carries.
pub fn render_full_markdown(cert: &X509Certificate, der: &[u8]) -> String {
    let registry = oid_registry();
    let rows = summary_rows(cert, der, &registry);

    let mut extensions = String::new();
    for ext in cert.extensions() {
        let name = extension_name(&ext.oid, &registry);
        let critical = if ext.critical { " (critical)" } else { "" };
        let body = match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => san
                .general_names
                .iter()
                .map(format_general_name)
                .collect::<Vec<_>>()
                .join(", "),
            ParsedExtension::KeyUsage(usage) => usage.to_string(),
            ParsedExtension::BasicConstraints(bc) => format!(
                "CA: {}, path length constraint: {}",
                if bc.ca { "yes" } else { "no" },
                bc.path_len_constraint
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
            ParsedExtension::SubjectKeyIdentifier(id) => format_hex(id.0),
            ParsedExtension::AuthorityKeyIdentifier(aki) => aki
                .key_identifier
                .as_ref()
                .map(|id| format!("Key ID: {}", format_hex(id.0)))
                .unwrap_or_else(|| "(no key identifier)".to_string()),
            ParsedExtension::ExtendedKeyUsage(eku) => {
                let mut purposes = Vec::new();
                if eku.any {
                    purposes.push("any");
                }
                if eku.server_auth {
                    purposes.push("server auth");
                }
                if eku.client_auth {
                    purposes.push("client auth");
                }
                if eku.code_signing {
                    purposes.push("code signing");
                }
                if eku.email_protection {
                    purposes.push("email protection");
                }
                if eku.time_stamping {
                    purposes.push("time stamping");
                }
                if eku.ocsp_signing {
                    purposes.push("OCSP signing");
                }
                purposes.join(", ")
            }
            other => format!("{other:?}"),
        };
        extensions.push_str(&format!("\n### {name}{critical}\n\n{body}\n"));
    }

    format!(
        "# X.509 Certificate\n\nVersion: v{}\n\n| Field | Value |\n|---|---|\n{}\n\n## Extensions\n{extensions}",
        cert.version().0 + 1,
        rows.join("\n")
    )
}
