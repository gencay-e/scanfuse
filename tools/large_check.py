"""Generate a large Nuclei file, run scanfuse on it and check that nothing was lost.

Usage:
    python tools/large_check.py 100000 [--formats json,csv,markdown] [--work DIR]

Half of the findings have a title of their own. The other half repeat those titles on other
hosts with other evidence, so they must be merged without losing a host or an evidence entry.
For each output format the script prints the run time, the peak memory of the scanfuse process
and the result of the checks. The exit code is 1 if any check fails.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def generate(path: Path, n: int) -> int:
    """Write n results. Returns the number of distinct titles."""
    unique = max(1, n // 2)
    with path.open("w", encoding="utf-8") as out:
        for i in range(n):
            t = i % unique
            out.write(json.dumps({
                "template-id": f"template-{t}",
                "host": f"host-{i}.example.test",
                "ip": f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}",
                "matched-at": f"http://host-{i}.example.test/p{t}",
                "info": {"name": f"Finding number {t}", "severity": ["info", "low", "medium", "high", "critical"][t % 5],
                         "description": f"Description of template {t}"},
                "request": f"GET /p{i} HTTP/1.1",
                "response": f"HTTP/1.1 200 OK\nunique-{i}",
            }) + "\n")
    return unique


def run_scanfuse(source: Path, out: Path, fmt: str) -> tuple[float, float, int, str]:
    """Run scanfuse once. Returns (seconds, peak memory in MB, exit code, output).

    The peak memory belongs to this one process (os.wait4). On Windows it is reported as 0.
    """
    cmd = [sys.executable, "-m", "scanfuse.cli", str(source), "-o", str(out), "--format-out", fmt]
    start = time.perf_counter()
    with tempfile.TemporaryFile() as log:
        proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)  # noqa: S603
        if hasattr(os, "wait4"):
            _pid, status, usage = os.wait4(proc.pid, 0)
            code = os.waitstatus_to_exitcode(status)
            peak_mb = usage.ru_maxrss / 1024  # Linux reports kilobytes
            if sys.platform == "darwin":
                peak_mb = usage.ru_maxrss / (1024 * 1024)  # macOS reports bytes
        else:
            code = proc.wait()
            peak_mb = 0.0
        seconds = time.perf_counter() - start
        log.seek(0)
        text = log.read().decode("utf-8", errors="replace")
    return seconds, peak_mb, code, text


def check(fmt: str, out: Path, n: int, unique: int) -> list[str]:
    problems: list[str] = []
    if fmt == "json":
        data = json.loads((out / "report.json").read_text(encoding="utf-8"))
        findings = data["findings"]
        if not data["complete"]:
            problems.append("report is marked incomplete")
        if len(findings) != unique:
            problems.append(f"{len(findings)} findings, expected {unique}")
        hosts = sum(len(f["hosts"]) for f in findings)
        evidence = sum(len(f["evidence"]) for f in findings)
        if hosts != n:
            problems.append(f"{hosts} hosts, expected {n}")
        if evidence != n:
            problems.append(f"{evidence} evidence entries, expected {n}")
        if len({f["title"] for f in findings}) != unique:
            problems.append("titles are not unique")
    elif fmt == "csv":
        with (out / "report.csv").open(newline="", encoding="utf-8") as stream:
            rows = list(csv.reader(stream))[1:]
        if len(rows) != unique:
            problems.append(f"{len(rows)} rows, expected {unique}")
        hosts = sum(len([h for h in r[3].split(", ") if h]) for r in rows)
        if hosts != n:
            problems.append(f"{hosts} hosts, expected {n}")
    else:
        md_files = [p for p in out.glob("*.md") if p.name != "index.md"]
        if len(md_files) != unique:
            problems.append(f"{len(md_files)} finding files, expected {unique}")
        if not (out / "report.html").exists():
            problems.append("report.html is missing")
        index = (out / "index.md").read_text(encoding="utf-8")
        if f"Total Findings: {unique}" not in index:
            problems.append("index.md has the wrong total")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("count", type=int)
    parser.add_argument("--formats", default="json,csv,markdown")
    parser.add_argument("--work", default=None, help="working directory (default: a temporary one)")
    args = parser.parse_args()

    work = Path(args.work) if args.work else Path(tempfile.mkdtemp(prefix="scanfuse-large-"))
    work.mkdir(parents=True, exist_ok=True)
    source = work / "input.jsonl"
    unique = generate(source, args.count)
    print(f"{args.count} results, {unique} distinct titles, input {source.stat().st_size / 1e6:.1f} MB")
    failed = False
    for fmt in args.formats.split(","):
        out = work / f"out-{fmt}"
        shutil.rmtree(out, ignore_errors=True)
        seconds, peak, code, text = run_scanfuse(source, out, fmt)
        problems = [] if code == 0 else [f"exit code {code}: {text[-300:]}"]
        if code == 0:
            problems += check(fmt, out, args.count, unique)
        status = "OK" if not problems else "FAILED"
        print(f"{fmt:9} {seconds:7.1f} s  peak {peak:7.0f} MB  {status}")
        for problem in problems:
            print(f"    - {problem}")
        failed = failed or bool(problems)
    if not args.work:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
