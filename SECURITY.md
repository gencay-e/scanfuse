# Security

## Reporting a vulnerability

Please report vulnerabilities privately and do not open a public issue. Use GitHub's private vulnerability reporting for this repository (Security tab, "Report a vulnerability").

Supported: the latest release.

## What scanfuse handles

scanfuse reads scanner files that may come from untrusted targets (titles, banners and evidence are attacker-controlled text) and writes Markdown, HTML, JSON, CSV, SARIF and PDF.

The threat model and trust boundaries are described in [docs/security-model.md](https://github.com/gencay-e/scanfuse/blob/main/docs/security-model.md).

* XML with entity declarations is rejected.
* Titles, host names and ids are escaped in Markdown and HTML. The HTML page removes scripts, images, frames and `javascript:` links.
* CSV cells that start with `=`, `+`, `-`, `@` or look-alike characters are prefixed with `'`.
* Nothing is sent over the network.

## Known limits

* Descriptions and remediation text keep Markdown, including links. Links are shown as the scanner wrote them.
* The HTML page and CSV output were checked by reading the files, not by opening them in a browser, Excel or LibreOffice.
* Format detection looks at the start of the file.
* Release programs are not signed. Releases come with a `SHA256SUMS` file.
