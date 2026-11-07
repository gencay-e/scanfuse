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
