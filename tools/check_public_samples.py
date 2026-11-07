"""Download real scanner output from the public DefectDojo sample repository and check scanfuse on it.

Usage: python tools/check_public_samples.py [--folder DIR]

Source: https://github.com/DefectDojo/sample-scan-files (MIT license). The files are downloaded into
a temporary folder (or --folder) and are not part of this repository. For each file the script
reads it with scanfuse, compares the number of findings with an independent count, merges the
findings, writes JSON, CSV and Markdown, and prints the time. The exit code is 1 if anything fails.
Needs network access to raw.githubusercontent.com.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import defusedxml.ElementTree as ET

from scanfuse.engine import ScanfuseEngine
from scanfuse.utils import deduplicate_findings

BASE = "https://raw.githubusercontent.com/DefectDojo/sample-scan-files/master/"
FILES = [
    "nmap/nmap_output_v7.12.xml",
    "nmap/nmap_v6.40.xml",
    "zap/zaproxy-demo-site_1.4.0.1.xml",
    "zap/zaproxy-wavsep_v1.4.0.1.xml",
    "trivy/juice_shop-trivy-report.json",
    "trivy/k-client_trivy-report.json",
    "trivy/kiem-trivy-sca-report.json",
    "trivy/trivy_mix.json",
    "trivy/trivy_v0.2.1_python3.json",
    "nessus/nessus-02_v_unknown.xml",
    "nessus/nessus_v_unknown.nessus",
    "burp/burpvulns_v2_1_02.xml",
]


def independent_count(path: Path) -> int:
    raw = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(raw)
        results = data if isinstance(data, list) else data.get("Results") or []
        return sum(len(r.get(k) or []) for r in results for k in ("Vulnerabilities", "Misconfigurations", "Secrets"))
    root = ET.fromstring(re.sub(r"<!DOCTYPE.*?\]>", "", raw, flags=re.S))
    if root.tag == "nmaprun":
        return sum(
            1 for h in root.iter("host") if (h.find("status") is None or h.find("status").get("state") == "up")
            for p in h.iter("port") if p.find("state") is not None and p.find("state").get("state") == "open"
        )
    counters = {"OWASPZAPReport": "alertitem", "NessusClientData_v2": "ReportItem", "issues": "issue"}
    return sum(1 for _ in root.iter(counters[root.tag]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", default=None)
    args = parser.parse_args()
    folder = Path(args.folder) if args.folder else Path(tempfile.mkdtemp(prefix="scanfuse-public-"))
    folder.mkdir(parents=True, exist_ok=True)
    failures = 0
    for name in FILES:
        target = folder / name.replace("/", "__")
        if not target.exists():
            urllib.request.urlretrieve(BASE + name, target)  # noqa: S310 - fixed https URL
        out = folder / ("out-" + target.stem)
        started = time.perf_counter()
        problem = ""
        findings: list = []
        try:
            engine = ScanfuseEngine(str(out))
            findings = engine.process_file(str(target), "auto")
            expected = independent_count(target)
            if len(findings) != expected:
                problem = f"parsed {len(findings)}, expected {expected}"
            merged = deduplicate_findings(findings)
            if {h.ip for f in findings for h in f.hosts} != {h.ip for f in merged for h in f.hosts}:
                problem = problem or "hosts changed while merging"
            if any(f.title.lower().startswith("unknown") for f in findings):
                problem = problem or "placeholder titles"
            engine.export_json(merged, replace=True)
            engine.export_csv(merged, replace=True)
            engine.export_findings(merged, replace=True)
        except Exception as e:  # noqa: BLE001 - report every kind of failure
            problem = f"{type(e).__name__}: {e}"[:150]
        seconds = time.perf_counter() - started
        failures += bool(problem)
        status = "FAIL" if problem else "ok  "
        print(f"{status} {seconds:5.1f}s {name:44} {len(findings):>5} findings  {problem}")
    print(f"\n{len(FILES) - failures}/{len(FILES)} files passed. Files are in {folder}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
