# X.509 Parser for Zed

Hover over a PEM-encoded X.509 certificate in [Zed](https://zed.dev) to see
who it was issued to, when it expires, its SANs and its fingerprint. A code
action decodes the full certificate into an `openssl x509 -text`-style file.

## Features

- **Hover** on any `-----BEGIN CERTIFICATE-----` block: subject, issuer,
  serial, validity (with an expiry countdown), signature algorithm, CA flag,
  SHA-256 fingerprint, SANs and key usage.
- **Code action "Decode certificate to file"**: writes `<name>.decoded.txt`
  next to the source file in `openssl x509 -text` format (public key,
  extensions, signature, original PEM) and opens it.
- PEM syntax highlighting via
  [tree-sitter-pem](https://github.com/tree-sitter-grammars/tree-sitter-pem).

Applies to files ending in `.pem`, `.crt`, `.cer`, `.cert`, or whose first line
starts with `-----BEGIN `.

## Install

Install **X.509 Parser** from the Zed extensions panel (`zed: extensions`).

The extension downloads the matching `x509-language-server` binary from this
repo's GitHub releases on first use. To use your own build instead, put
`x509-language-server` on your `PATH`; it takes priority:

```sh
cargo install --git https://github.com/hvardhan20/zed-x509-parser x509-language-server
```

Supported prebuilt platforms: macOS (arm64, x86_64), Linux (arm64, x86_64),
Windows (x86_64).

## Limitations

- Only PEM text is decoded. Binary DER files (common for `.cer`) are not
  readable as text in the editor, so the server never sees them.
- Only certificates are decoded. Other PEM blocks (keys, CSRs) are ignored.

## Development

```
extension/        Zed extension (Rust -> wasm) + PEM language config
language-server/  LSP server (hover, code action, decoding)
```

```sh
# server
cd language-server && cargo test

# extension: in Zed, run `zed: install dev extension` and pick ./extension
```

For a dev extension, build the server and put it on `PATH`
(`cargo install --path language-server`).

### Releasing

Tag and push; the `Release` workflow builds all platforms and attaches
`x509-language-server-<target>.tar.gz` (`.zip` on Windows) to the release.

```sh
git tag v0.1.0 && git push origin v0.1.0
```

Bump `version` in `extension/extension.toml` and `extension/Cargo.toml` to
match, then open a PR against
[zed-industries/extensions](https://github.com/zed-industries/extensions)
(add this repo as a submodule with `path = "extension"` and an entry in
`extensions.toml`).

## License

MIT
