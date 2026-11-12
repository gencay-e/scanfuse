# Changelog

## 1.0.2 (2026-11-12)

* README and SECURITY list SARIF and PDF output.
* Package metadata links the homepage, documentation and issues, and marks the project as stable.
* `scanfuse --help` shows the exit codes in clean lines.

## 1.0.1 (2026-11-11)

Documentation and release fixes, no change to how reports are made.

* The images on the PyPI page were missing because the README used relative paths. They now point to GitHub.
* The screenshots show the 1.0.0 report with the theme menu, the flow image lists the SARIF and PDF output, and the example report in `examples/` was made again with 1.0.0.
* The package description on PyPI and in `scanfuse --help` names all output formats.
* Release workflow: the upload to PyPI waits for the standalone programs, so a failed program build no longer leaves a release on PyPI without archives on GitHub.

## 1.0.0 (2026-11-11)

First stable release. The command line, `.scanfuse.yaml` and the JSON format (`schema_version` 2) are now kept compatible within 1.x. The new input formats below are experimental and may still change.

### Added

* **SARIF and PDF output.** `--format-out sarif` writes `report.sarif` (SARIF 2.1.0), `--format-out pdf` writes `report.pdf` with one page per finding.
* **Experimental input formats:** SARIF 2.1.0, Semgrep JSON, Grype JSON, Nikto JSON and XML, testssl.sh JSON (`--jsonfile` and `--jsonfile-pretty`). They are not detected automatically; set them with `-f`.
* **`overrides` and `exclusions` in `.scanfuse.yaml`.** Overrides change the severity of matching findings or add tags; exclusions leave them out. Rules match on `cve`, `tool_id`, `port` and `host` (wildcards).
* **Report themes.** `report.html` has a System, Light and Dark switch and remembers the choice.
* New JSON fields: `tags` and `cvss_merge_conflict` (true when merged findings had CVSS vectors with different base metrics) on findings, `port` on hosts, `code` on evidence.
* Release archives contain `THIRD_PARTY_LICENSES.txt`.

### Changed

* Findings are merged first, then `.scanfuse.yaml` rules, `--min-severity` and `--host` are applied. Before, filters ran before merging, so a merged finding could lose the evidence of another tool or end up with a lower severity.
* `cvss_score` must be between 0 and 10. Values outside are dropped instead of written to the report.
* New dependency: `fpdf2` (LGPL-3.0) for the PDF output.

### Fixed

* 28 edge cases from an audit of the parsers (Burp, Nessus, Nmap, Nuclei, Trivy, ZAP), merging and formula escaping.
* Nessus keeps both the IPv4 and the IPv6 address of a host.
* Nmap keeps OS guesses without an accuracy value.
* Trivy files with invalid CVSS fields are read; the invalid values are skipped.
* A Nuclei JSON array with some invalid entries reports the import as partial instead of failing.
* Lines starting with `#` in titles and descriptions can no longer create Markdown headings.
* Indentation inside fenced code blocks in scanner descriptions is kept.
* CSV formula escaping also catches leading control characters and zero-width characters.
* Empty entries in `ignore_titles` no longer hide every finding.

## 0.2.0 (2026-11-07)

The project is renamed from `repx` to `scanfuse` (the name `repx` is taken on PyPI). The command, the Python package, the configuration file (`.repx.yaml` is now `.scanfuse.yaml`) and the environment variable for the packaged-program tests (`REPX_EXE` is now `SCANFUSE_EXE`) changed. repx 0.1 was never published.

This version changes the JSON format and the merge rules. Read "Changed" before you update scripts.

### Changed

* **`report.json` is now an object**, not a list: `{"schema_version": 2, "complete": true, "errors": [], "findings": [...]}`. Scripts that read the list must read `["findings"]` instead.
* **Merging is stricter.** Findings are merged only when the titles are equal (ignoring case and surrounding spaces), they have the same CVE or GHSA ids and the same port, and the same tool does not give them different tool ids. Similar titles are no longer merged. A merged finding keeps every host and every piece of evidence, and the description, remediation, severity, CVSS score and vector of each tool are listed in `sources`.
* CSV: `Hosts` shows `ip (host name)` when a host name is known. Six columns were added after the original eight: `CVSS Vector`, `Port`, `Identifiers`, `References`, `Other Reports`, `Import Status`.
* `--host` matches the IP or host name exactly (ignoring case). Before, it matched any part of the text, so `10.0.0.1` also matched `10.0.0.10`. `*` and `?` are wildcards.
* `--min-severity`, `--format`, `--format-out` accept only their documented values. `--template-dir` must exist. A wrong value now stops with exit code 2.
* An invalid `.scanfuse.yaml` (wrong types, not a mapping, YAML syntax error) is an error: exit code 1 and an incomplete report.
* The Markdown index lists findings by severity (before: alphabetically by severity name).
* Titles, host names, ids and tool names are escaped in the Markdown, so scanner text cannot add links or headings there. Descriptions keep their formatting but cannot create headings.
* Version 0.2.0. The version is defined only in `scanfuse/__init__.py`.

### Added

* **References and CWE ids.** Links that the scanner gives for a finding (ZAP `reference`, Burp `references`, Nessus `see_also`, Trivy `References` and `PrimaryURL`, Nuclei `info.reference`) are kept in the new field `references`. They appear under "References" in the Markdown and HTML report, in the JSON, and in the new CSV column `References`. CWE ids (ZAP `cweid`, Burp classifications, Trivy `CweIDs`) are identifiers. WASC ids from ZAP too.
* Nessus: the synopsis is put in front of the description, CVSS v3 is used if there is no v2 score, and the placeholder solution "n/a" is no longer shown as a remediation. Burp: confidence and location are kept in an evidence entry.
* `tools/check_public_samples.py` downloads the twelve public files, compares the number of findings with an independent count, merges, exports in all formats and prints the time. All twelve pass; the largest (2,587 ZAP alerts, 1,427 Trivy findings) take 1.4 s.
* Existing reports are protected. scanfuse stops with exit code 2 if files would be overwritten. With `--replace`, it builds the new report in a temporary folder and attempts to restore the old report if publication fails. A failed recovery retains backups; a process or system crash can leave a mixed report.
* A Nuclei JSONL file with malformed lines retains valid findings and marks the report incomplete.
* Reports from partly failed runs are marked: `complete: false` and `errors` in the JSON, an INCOMPLETE notice in `index.md` and `report.html`, and an `Import Status` column in the CSV.
* Ids and ports are kept: CVE, GHSA and CWE ids, and tool ids such as `nessus-plugin:12345`, as `identifiers`, and the port as `port`.
* Evidence records which tool reported it when findings are merged.
* `--csv-excel` (byte order mark, `;` separator), `--replace`, `--version`.
* MIT `LICENSE`, package metadata, a source package without internal files.
* `tools/large_check.py` for large inputs. CI builds and tests standalone programs on Linux, Windows and macOS, runs the tests on Python 3.12 and 3.13, checks the dependencies with pip-audit and installs the wheel in a clean environment.

### Fixed

Found by running scanfuse on twelve real scanner files from the public [DefectDojo sample-scan-files](https://github.com/DefectDojo/sample-scan-files) repository (MIT license): Nmap 6.40 and 7.12, ZAP 1.4, Trivy (three schemas), Nessus, Burp.

* **Burp files were not detected.** The format check read 1,024 characters, but Burp writes a long DTD in front of the first tag (`<issues>` starts at about byte 3,400). The file was then read as nmap and failed. scanfuse now reads 64 KB.
* **Older Trivy files were not read.** They are a plain JSON list of results without `SchemaVersion`. They were taken for Nuclei and failed. Both Trivy schemas are supported now.
* **ZAP 1.x reports gave one finding titled "Unknown Vulnerability".** Old ZAP files have `<alert>` instead of `<name>` and keep the URL, parameter and attack in the alert itself instead of in `<instances>`. In the sample, all 67 alerts had the same title, were merged into one, and lost their URLs. Now the title, the affected URL, the parameter, the attack and the other info are read. Newer ZAP files also keep `param`, `attack` and `otherinfo` of every instance now.
* Burp, ZAP and Nessus text fields contain HTML (`<p>`, `<br>`, `<li>`, `&quot;`). The report showed the markup as text. It is converted to plain text now, with line breaks and list items kept.
* nmap: the operating system guess was dropped. The guess with the highest accuracy is kept now, for example `Linux 5.0 - 5.7 (97%)`. The CPE names that version detection reports (`cpe:/a:...`) were dropped too and are kept as identifiers. Found by running nmap 7.94 against the local machine and comparing its XML with scanfuse's output.
* A scan without any open port (host down, all ports closed, list scan) ended without a word. scanfuse now says that the input contains no findings and that nothing was exported.
* Merging lost data: description, remediation, CVSS score and vector of the other tools, findings with the same title but different CVEs, packages or ports, and the second operating system of a host.
* A finding titled "Index" or "Report", or named like a Windows device (`CON`, `NUL`, `COM1`), overwrote or collided with other files.
* Evidence was escaped twice and changed (`<` became `&lt;`, three backticks became `'''`). It is now written unchanged inside a code fence that is longer than any backtick run in the data.
* Formula protection in CSV missed look-alike characters such as a full-width `＝` and a leading no-break space.
* `-f nuclei` on a file of another format produced a bogus finding. It is now an error.
* A missing file was reported as "could not auto-detect format". A directory or an output path that is a file caused a traceback. XML with entities gave a raw exception name. Messages for standard input showed the name of a temporary file. Square brackets in a file name could break the output.
* The wheel and the source package had no license, and the source package contained local planning files with user paths.

### Measured

Not a reference system: one Linux machine in the cloud (Ubuntu glibc 2.39, 4 CPUs, 16 GB). 100,000 results, 50,000 distinct titles, each repeated on another host with other evidence. All hosts, all evidence entries and the number of findings were checked after each run.

| Output | Time | Peak memory |
|---|---|---|
| JSON | 13.9 s | 909 MB |
| CSV | 10.4 s | 687 MB |
| Markdown with index and HTML | 123.9 s | 1040 MB |

### Checked with real scanner output

* Nmap 7.94 was run against 127.0.0.1: service and version scan with scripts, OS detection, a scan with only closed ports, a host discovery scan and a list scan. Two of those files are in `tests/fixtures/` (`real_nmap_*`).
* Twelve public files from the DefectDojo sample repository (see above). Eight of them are in `tests/fixtures/public/` with their license; the rest are downloaded by `tools/check_public_samples.py`.
* Nuclei has no public sample file in that repository. The Nuclei parser is still tested only with hand-made files. A real Nuclei export would help.
* The sample files are old (2013 to 2024). Current versions of ZAP, Burp, Nessus and Trivy may have fields that these files do not show.

### Not checked

* The HTML report in a browser by hand (search, severity filter, keyboard, narrow window).
* The CSV in Excel and LibreOffice. Only the file content was checked.
* Standalone programs on other Linux distributions (Debian, Kali, Fedora, Arch, Alpine), Linux on ARM and macOS on Intel.
* Whether the Windows program starts on a clean Windows 11 machine without developer tools. CI builds and tests it on a Windows runner.

## 0.1.0

First version, then called repx. Not published.
