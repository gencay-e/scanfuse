# Public sample scans

Real scanner output from <https://github.com/DefectDojo/sample-scan-files> (MIT license, Copyright (c) 2018
DefectDojo, see `LICENSE-DefectDojo-sample-scan-files`). The files are used unchanged, with one exception:
`nessus_v_unknown_two_smallest_hosts.nessus` is `nessus/nessus_v_unknown.nessus` cut down to its two smallest hosts and without the `Policy` section, which scanfuse does not read.

| File | Origin (folder in the source repository) |
|---|---|
| `nmap_output_v7.12.xml`, `nmap_v6.40.xml` | `nmap/` |
| `zaproxy-demo-site_1.4.0.1.xml` | `zap/` |
| `juice_shop-trivy-report.json`, `k-client_trivy-report.json`, `trivy_mix.json` | `trivy/` |
| `burpvulns_v2_1_02.xml` | `burp/` |
| `nessus_v_unknown_two_smallest_hosts.nessus` | `nessus/` |

Larger files from the same repository are checked by `tools/check_public_samples.py`, which downloads them.

## Extended samples

The files in `extended/` are reduced extracts. All addresses and target names in the Nikto and Nuclei extracts were replaced with `192.0.2.1` and `example.test`; Nikto XML links and metadata were removed. Nuclei timestamps and extracted results were removed. Its JSON array was converted from the same two JSONL records. Semgrep paths and the CodeQL location were replaced with example paths. The SARIF files retain one result and its rule; other results and metadata were removed. The Grype extract retains one match and a replacement source name.

| Files | Original | License |
|---|---|---|
| `nuclei.json`, `nuclei.jsonl` | [Nuclei](https://github.com/DefectDojo/django-DefectDojo/blob/f6cee25f3e0fca85c8ccfc6e3764a4e69a2f0c0f/unittests/scans/nuclei/many_findings.json) | BSD-3-Clause, `extended/LICENSE-DefectDojo` |
| `codeql.sarif` | [CodeQL](https://github.com/DefectDojo/django-DefectDojo/blob/f6cee25f3e0fca85c8ccfc6e3764a4e69a2f0c0f/unittests/scans/codeql/one_finding.sarif) | BSD-3-Clause |
| `nikto.json` | [Nikto JSON](https://github.com/DefectDojo/django-DefectDojo/blob/f6cee25f3e0fca85c8ccfc6e3764a4e69a2f0c0f/unittests/scans/nikto/juice-shop.json) | BSD-3-Clause |
| `nikto.xml` | [Nikto XML](https://github.com/DefectDojo/sample-scan-files/blob/d94932669eabf83172d66bee84233d366bef43a4/nikto/nikto.xml) | MIT |
| `nikto.csv` | Synthetic local capture with Nikto 2.6.1 against a temporary loopback HTTP server (loopback addresses sanitized to `192.0.2.1`; single header row retained). | Generated scan output only; Nikto code and non-free databases are not included |
| `grype.json` | [Grype](https://github.com/DefectDojo/sample-scan-files/blob/d94932669eabf83172d66bee84233d366bef43a4/anchore_grype/grype_nginx.json) | MIT |
| `semgrep.json`, `semgrep.sarif` | [JSON](https://github.com/DefectDojo/sample-scan-files/blob/d94932669eabf83172d66bee84233d366bef43a4/semgrep/owasp-benchmark-sample.json), [SARIF](https://github.com/DefectDojo/sample-scan-files/blob/d94932669eabf83172d66bee84233d366bef43a4/semgrep/owasp-benchmark-sample.sarif) | MIT |

The testssl extracts retain two reported checks each. Hostnames and IPs were replaced with `example.test` and `192.0.2.1`; other scan metadata was removed.

| Files | Original | License |
|---|---|---|
| `testssl-flat.json` | [Flat testssl report](https://github.com/happyc0ding/vulnscan-parser/blob/8233ff3c1e2282bb5bda177ecefdc1745c3003d7/tests/data/testssl/v3.0/json/normal/testssl_104.154.89.105-TCP-443-expired.badssl.com.json) | MIT, `extended/LICENSE-vulnscan-parser` |
| `testssl-pretty.json` | [Structured testssl report](https://github.com/bitsofinfo/testssl.sh-alerts/blob/c5cff897598691c19e6ae35189fd3bf2ec7a0ec4/sample/20181113_194917-www.google.com-testssl_cmds/www.google.com/20181108120000/public/search/20181108120000_testssl_www.google.com.json) | Apache-2.0, `extended/LICENSE-testssl-alerts` |
