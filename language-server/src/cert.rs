use oid_registry::OidRegistry;
use sha2::{Digest, Sha256};
use x509_parser::extensions::{ExtendedKeyUsage, GeneralName, ParsedExtension};
use x509_parser::prelude::X509Certificate;
use x509_parser::public_key::PublicKey;

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

fn oid_short_name(oid: &x509_parser::der_parser::Oid, registry: &OidRegistry) -> String {
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

fn format_extended_key_usage(eku: &ExtendedKeyUsage) -> String {
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

/// Hex-dumps `bytes` as colon-separated byte pairs, `per_line` bytes to a
/// line, each line prefixed with `indent` (matching openssl's `x509 -text`
/// wrapping: lowercase for key material, uppercase for identifiers).
fn wrap_hex(bytes: &[u8], per_line: usize, indent: &str, upper: bool) -> String {
    let tokens: Vec<String> = bytes
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect();
    let lines: Vec<String> = tokens.chunks(per_line).map(|c| c.join(":")).collect();
    format!("{indent}{}", lines.join(&format!(":\n{indent}")))
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

/// Concise summary for the hover tooltip: identity, validity, and only the
/// two extensions people usually care about at a glance.
pub fn render_markdown(cert: &X509Certificate, der: &[u8]) -> String {
    let registry = oid_registry();
    let validity = cert.validity();
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
        format!(
            "| Valid to | {} ({}) |",
            validity.not_after,
            expiry_note(cert)
        ),
        format!(
            "| Signature algorithm | {} |",
            oid_short_name(&cert.signature_algorithm.algorithm, &registry)
        ),
        format!("| CA | {} |", if is_ca { "yes" } else { "no" }),
        format!("| SHA-256 fingerprint | `{}` |", fingerprint_sha256(der)),
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

/// Full `openssl x509 -text`-style dump written to the `.decoded.txt` file,
/// followed by the original PEM block.
pub fn render_openssl_style(cert: &X509Certificate, pem_text: &str) -> String {
    let registry = oid_registry();
    let mut out = String::new();

    out.push_str("Certificate:\n");
    out.push_str("    Data:\n");
    out.push_str(&format!(
        "        Version: {} (0x{:x})\n",
        cert.version().0 + 1,
        cert.version().0
    ));
    out.push_str("        Serial Number:\n");
    out.push_str(&format!("            {}\n", cert.raw_serial_as_string()));
    out.push_str(&format!(
        "        Signature Algorithm: {}\n",
        oid_short_name(&cert.signature_algorithm.algorithm, &registry)
    ));
    out.push_str(&format!("        Issuer: {}\n", cert.issuer()));
    out.push_str("        Validity\n");
    out.push_str(&format!(
        "            Not Before: {}\n",
        format_openssl_time(&cert.validity().not_before.to_string())
    ));
    out.push_str(&format!(
        "            Not After : {}\n",
        format_openssl_time(&cert.validity().not_after.to_string())
    ));
    out.push_str(&format!("        Subject: {}\n", cert.subject()));
    out.push_str("        Subject Public Key Info:\n");

    let public_key = cert.public_key();
    match public_key.parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            out.push_str("            Public Key Algorithm: rsaEncryption\n");
            out.push_str(&format!(
                "                Public-Key: ({} bit)\n",
                rsa.key_size()
            ));
            out.push_str("                Modulus:\n");
            out.push_str(&wrap_hex(rsa.modulus, 15, "                    ", false));
            out.push('\n');
            let exponent = rsa.try_exponent().unwrap_or(0);
            out.push_str(&format!(
                "                Exponent: {exponent} (0x{exponent:x})\n"
            ));
        }
        Ok(PublicKey::EC(ec)) => {
            out.push_str(&format!(
                "            Public Key Algorithm: {}\n",
                oid_short_name(&public_key.algorithm.algorithm, &registry)
            ));
            out.push_str(&format!(
                "                Public-Key: ({} bit)\n",
                ec.key_size()
            ));
            out.push_str("                pub:\n");
            out.push_str(&wrap_hex(ec.data(), 15, "                    ", false));
            out.push('\n');
        }
        _ => {
            out.push_str(&format!(
                "            Public Key Algorithm: {}\n",
                oid_short_name(&public_key.algorithm.algorithm, &registry)
            ));
        }
    }

    out.push_str("        X509v3 extensions:\n");
    for ext in cert.extensions() {
        let (title, body) = match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => (
                "X509v3 Subject Key Identifier".to_string(),
                wrap_hex(id.0, 20, "                ", true),
            ),
            ParsedExtension::AuthorityKeyIdentifier(aki) => (
                "X509v3 Authority Key Identifier".to_string(),
                aki.key_identifier
                    .as_ref()
                    .map(|id| wrap_hex(id.0, 20, "                ", true))
                    .unwrap_or_default(),
            ),
            ParsedExtension::BasicConstraints(bc) => (
                "X509v3 Basic Constraints".to_string(),
                format!(
                    "                CA:{}{}",
                    if bc.ca { "TRUE" } else { "FALSE" },
                    bc.path_len_constraint
                        .map(|n| format!(", pathlen:{n}"))
                        .unwrap_or_default()
                ),
            ),
            ParsedExtension::SubjectAlternativeName(san) => (
                "X509v3 Subject Alternative Name".to_string(),
                format!(
                    "                {}",
                    san.general_names
                        .iter()
                        .map(format_general_name)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ),
            ParsedExtension::KeyUsage(usage) => (
                "X509v3 Key Usage".to_string(),
                format!("                {usage}"),
            ),
            ParsedExtension::ExtendedKeyUsage(eku) => (
                "X509v3 Extended Key Usage".to_string(),
                format!("                {}", format_extended_key_usage(eku)),
            ),
            other => (
                format!("X509v3 {}", oid_short_name(&ext.oid, &registry)),
                format!("                {other:?}"),
            ),
        };
        let critical = if ext.critical { " critical" } else { " " };
        out.push_str(&format!("            {title}:{critical}\n{body}\n"));
    }

    out.push_str(&format!(
        "    Signature Algorithm: {}\n",
        oid_short_name(&cert.signature_algorithm.algorithm, &registry)
    ));
    out.push_str("    Signature Value:\n");
    out.push_str(&wrap_hex(
        cert.signature_value.as_ref(),
        18,
        "        ",
        false,
    ));
    out.push('\n');

    out.push_str(pem_text);
    out.push('\n');

    out
}

/// x509-parser's `ASN1Time` prints e.g. "Jul  8 19:54:13 2026 +00:00";
/// X.509 timestamps are always UTC, so match openssl's "... GMT" rendering.
fn format_openssl_time(display: &str) -> String {
    display.replacen("+00:00", "GMT", 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::pem::parse_x509_pem;

    const PEM: &str = include_str!("../tests/fixtures/example.pem");
    const GOLDEN: &str = include_str!("../tests/fixtures/example.decoded.txt");

    fn pem_block() -> &'static str {
        find_pem_block_at(PEM, 10).expect("block").text
    }

    #[test]
    fn finds_block_containing_offset() {
        let block = find_pem_block_at(PEM, 10).expect("block");
        assert_eq!(block.label, "CERTIFICATE");
        assert!(block.text.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(block.text.ends_with("-----END CERTIFICATE-----"));
        assert_eq!(&PEM[block.start..block.end], block.text);
    }

    #[test]
    fn no_block_outside_pem() {
        let text = format!("hello\n{}\ntrailer", pem_block());
        assert!(find_pem_block_at(&text, 2).is_none());
        assert!(find_pem_block_at(&text, text.len() - 2).is_none());
    }

    #[test]
    fn picks_the_right_block_among_several() {
        let text = format!(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n{}",
            pem_block()
        );
        let at_second = text.len() - 5;
        assert_eq!(
            find_pem_block_at(&text, at_second).unwrap().label,
            "CERTIFICATE"
        );
        assert_eq!(find_pem_block_at(&text, 5).unwrap().label, "PRIVATE KEY");
    }

    #[test]
    fn unterminated_block_is_ignored() {
        assert!(find_pem_block_at("-----BEGIN CERTIFICATE-----\nAAAA", 5).is_none());
    }

    #[test]
    fn certificate_labels() {
        assert!(is_certificate_label("CERTIFICATE"));
        assert!(is_certificate_label("X509 CERTIFICATE"));
        assert!(!is_certificate_label("PRIVATE KEY"));
    }

    #[test]
    fn openssl_style_matches_golden_file() {
        let (_, pem) = parse_x509_pem(pem_block().as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();
        assert_eq!(render_openssl_style(&cert, pem_block()), GOLDEN);
    }

    #[test]
    fn hover_markdown_has_key_fields() {
        let (_, pem) = parse_x509_pem(pem_block().as_bytes()).unwrap();
        let cert = pem.parse_x509().unwrap();
        let md = render_markdown(&cert, &pem.contents);
        assert!(md.contains("CN=example.com"));
        assert!(md.contains("sha256WithRSAEncryption"));
        assert!(md.contains("SHA-256 fingerprint"));
    }

    #[test]
    fn helpers_format_as_openssl_does() {
        assert_eq!(format_ip(&[10, 0, 0, 1]), "10.0.0.1");
        assert_eq!(
            wrap_hex(&[0xab, 0x01, 0xff], 2, "  ", true),
            "  AB:01:\n  FF"
        );
        assert_eq!(
            format_openssl_time("Jul  8 19:54:13 2026 +00:00"),
            "Jul  8 19:54:13 2026 GMT"
        );
    }
}
