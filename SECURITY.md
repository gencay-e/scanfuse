# Security

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's [private vulnerability reporting](https://github.com/gencay-e/scanfuse/security/advisories/new) rather than opening a public issue.

Supported versions: `1.2.x`.

## Security controls

`scanfuse` parses untrusted scanner output offline and writes Markdown, standalone HTML, JSON, CSV, SARIF, and PDF reports. The full threat model is documented in [docs/security-model.md](https://github.com/gencay-e/scanfuse/blob/main/docs/security-model.md).

* XML parsers use `defusedxml` to block external entities and entity expansion and never fetch external DTDs.
* Titles, host names, and IDs are escaped as plain text in Markdown and HTML. Standalone HTML is cleaned through an `nh3` allowlist permitting only formatting tags and `http`, `https`, and `mailto` URLs.
* CSV cells starting (after NFKC normalization and skipping leading whitespace, control, or formatting characters) with `=`, `+`, `-`, or `@`, as well as raw values starting with `\t`, `\r`, `\n`, space, or `\ufeff`, are prefixed with `'`.
* No outbound network connections are made.

## Known limits

* Scanner descriptions and remediation text keep Markdown formatting, including `http`/`https` links as reported by the scanner.
* Format auto-detection inspects file headers and XML root tags. Empty JSON arrays (`[]`) default to Nuclei; pass `--format` when an input file is ambiguous.
* Release binaries ship with `SHA256SUMS` checksums and are not code-signed or notarized.
* Spreadsheet formula handling is verified against Windows Excel Power Query where installed; other spreadsheet tools and browser engines are outside automated CI coverage.
