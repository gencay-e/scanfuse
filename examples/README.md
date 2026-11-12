# Example

`sample-report/` is a report made from six real scan files of five tools. The files come from the public
[DefectDojo sample-scan-files](https://github.com/DefectDojo/sample-scan-files) repository (MIT license) and are
kept in `tests/fixtures/public/`. They were made on demo systems.

```bash
cd tests/fixtures/public
scanfuse nmap_output_v7.12.xml zaproxy-demo-site_1.4.0.1.xml juice_shop-trivy-report.json \
  k-client_trivy-report.json burpvulns_v2_1_02.xml nessus_v_unknown_two_smallest_hosts.nessus \
  -o ../../../examples/sample-report --min-severity Medium --replace
```

Result: the six files hold 206 findings. Merging the same finding on several hosts leaves 162, and 49 of them are Medium or higher. (With 1.0.2 the same files gave 104 and 39: ZAP and Burp findings with the same title at different URL paths were merged then. Version 1.1.0 gives the same numbers for these files.) `--replace` is only needed if the folder already holds a report.

* `sample-report/report.html`: one HTML file with search and a severity filter. It needs no network.
* `sample-report/index.md`: the summary with the risk matrix and the list of findings.
* `sample-report/*.md`: one page per finding.

The merge in this example is small. It combines the same finding on several hosts. A finding reported by two tools is
merged when the title, the ids, the port and the set of HTTP methods and locations (URL path, case-sensitive) are equal; both descriptions are kept under "Reported by".
