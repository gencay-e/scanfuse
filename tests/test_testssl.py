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
