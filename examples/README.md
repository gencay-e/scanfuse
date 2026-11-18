# Example Report

`sample-report/` is generated from six public scan files across five tools (Nmap, OWASP ZAP, Trivy, Burp Suite, and Nessus) from [DefectDojo sample-scan-files](https://github.com/DefectDojo/sample-scan-files) (MIT license), stored in `tests/fixtures/public/`.

```bash
cd tests/fixtures/public
scanfuse nmap_output_v7.12.xml zaproxy-demo-site_1.4.0.1.xml juice_shop-trivy-report.json \
  k-client_trivy-report.json burpvulns_v2_1_02.xml nessus_v_unknown_two_smallest_hosts.nessus \
  -o ../../../examples/sample-report --min-severity Medium --replace
```

Running this command parses 206 raw findings, merges them into 162 unique findings, and exports the 49 findings rated Medium or higher into `examples/sample-report/`:

* `report.html`: self-contained HTML report with search, severity filtering, and light/dark themes.
* `index.md`: executive summary, risk matrix, findings overview, and affected hosts.
* `*.md`: one Markdown detail page per finding.

Findings with the same title, shared identifiers, port, and affected `(method, location)` pairs can be merged. Location matching is case-sensitive, and distinct tool-local ID groups from the same scanner stay separate. The report retains per-tool descriptions under **Reported by** and labels evidence with its source.
