import json
from pathlib import Path

import pytest

from scanfuse.parsers.testssl import TestsslParser

FIXTURE = Path(__file__).parent / "fixtures" / "testssl.json"


def test_testssl_flat_json_maps_severity_host_port_and_ids():
    findings = TestsslParser().parse(str(FIXTURE))
    by_id = {f.title: f for f in findings}
    # OK, INFO and WARN lines are not findings.
    assert sorted(by_id) == ["BREACH", "SSLv3", "TLS1", "heartbleed"]
    heartbleed = by_id["heartbleed"]
    assert heartbleed.severity == "Critical"
    assert "CVE-2014-0160" in heartbleed.identifiers
    assert "CWE-119" in heartbleed.identifiers
    assert heartbleed.hosts[0].ip == "192.0.2.20"
    assert heartbleed.hosts[0].hostname == "web.test"
    assert heartbleed.port == "443"
    assert "VULNERABLE" in heartbleed.description
    assert by_id["SSLv3"].severity == "High"
    assert by_id["BREACH"].severity == "Medium"
    assert by_id["TLS1"].severity == "Low"


def test_testssl_pretty_json_scan_result(tmp_path):
    path = tmp_path / "pretty.json"
    checks = [{k: v for k, v in c.items() if k not in ("ip", "port")}
              for c in json.loads(FIXTURE.read_text(encoding="utf-8"))]
    path.write_text(json.dumps({"scanResult": [{
        "targetHost": "web.test", "ip": "192.0.2.20", "port": "443", "service": "HTTP",
        "protocols": checks[:4], "vulnerabilities": checks[4:],
    }]}), encoding="utf-8")
    findings = TestsslParser().parse(str(path))
    assert sorted(f.title for f in findings) == ["BREACH", "SSLv3", "TLS1", "heartbleed"]
    assert all(f.hosts[0].ip == "192.0.2.20" and f.port == "443" for f in findings)


def test_testssl_fatal_is_an_error(tmp_path):
    path = tmp_path / "fatal.json"
    path.write_text(json.dumps([{"id": "scanProblem", "ip": "192.0.2.1", "port": "443",
                                 "severity": "FATAL", "finding": "Can't connect"}]), encoding="utf-8")
    with pytest.raises(ValueError):
        TestsslParser().parse(str(path))


@pytest.mark.parametrize("key", ["scanResult", "results", "findResults"])
def test_testssl_rejects_null_result_container(tmp_path, key):
    path = tmp_path / "null.json"
    path.write_text(json.dumps({key: None}), encoding="utf-8")
    with pytest.raises(ValueError, match="must be a list"):
        TestsslParser().parse(str(path))


@pytest.mark.parametrize("bad", [None, {"id": "SSLv3", "severity": "HIGH"}, "bad", 42])
def test_testssl_pretty_rejects_malformed_category(tmp_path, bad):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"scanResult": [{"targetHost": "example.test", "protocols": bad}]}),
                    encoding="utf-8")
    with pytest.raises(ValueError, match="protocols.*must be a list"):
        TestsslParser().parse(str(path))


@pytest.mark.parametrize("bad", [None, {}, "bad", {"severity": "HIGH"}])
def test_testssl_pretty_preserves_findings_on_invalid_nested_check(tmp_path, bad):
    from scanfuse.parsers.base import PartialImportError

    path = tmp_path / "partial.json"
    path.write_text(json.dumps({"scanResult": [{
        "targetHost": "example.test", "port": "443",
        "protocols": [{"id": "SSLv3", "severity": "HIGH", "finding": "enabled"}, bad],
    }]}), encoding="utf-8")
    with pytest.raises(PartialImportError) as exc:
        TestsslParser().parse(str(path))
    assert [f.title for f in exc.value.findings] == ["SSLv3"]


def test_testssl_pretty_preserves_other_categories_on_malformed_category(tmp_path):
    from scanfuse.parsers.base import PartialImportError

    path = tmp_path / "partial.json"
    path.write_text(json.dumps({"scanResult": [{
        "targetHost": "example.test", "protocols": None,
        "vulnerabilities": [{"id": "heartbleed", "severity": "HIGH"}],
    }]}), encoding="utf-8")
    with pytest.raises(PartialImportError) as exc:
        TestsslParser().parse(str(path))
    assert [f.title for f in exc.value.findings] == ["heartbleed"]


@pytest.mark.parametrize("category", ["protocols", "serverDefaults", "vulnerabilities"])
def test_testssl_pretty_accepts_empty_categories_and_target_metadata(tmp_path, category):
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"scanResult": [{
        "targetHost": "example.test", "ip": "192.0.2.1", "port": "443",
        "service": "HTTP", "rDNS": "example.test", category: [],
    }]}), encoding="utf-8")
    assert TestsslParser().parse(str(path)) == []


@pytest.mark.parametrize("protocols", [None, {"id": "SSLv3", "severity": "HIGH"}])
def test_testssl_invalid_category_marks_cli_report_incomplete_without_resolving_baseline(
    tmp_path, monkeypatch, protocols,
):
    from typer.testing import CliRunner

    from scanfuse.cli import app
    from scanfuse.engine import ScanfuseEngine

    monkeypatch.chdir(tmp_path)
    old_scan = tmp_path / "old.json"
    old_scan.write_text(json.dumps([{"id": "SSLv3", "severity": "HIGH"}]), encoding="utf-8")
    baseline = tmp_path / "baseline"
    ScanfuseEngine(str(baseline)).export_json(TestsslParser().parse(str(old_scan)))
    scan = tmp_path / "scan.json"
    scan.write_text(json.dumps({"scanResult": [{"targetHost": "example.test", "protocols": protocols}]}),
                    encoding="utf-8")
    output = tmp_path / "out"
    result = CliRunner().invoke(app, [str(scan), "-f", "testssl", "--baseline",
                                    str(baseline / "report.json"), "--format-out", "json", "-o", str(output)])
    assert result.exit_code == 1
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False
    assert report["errors"]
    assert report["resolved"] == []
