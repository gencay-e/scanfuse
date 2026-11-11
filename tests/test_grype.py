import json

from scanfuse.parsers.grype import GrypeParser


def test_grype_parser(tmp_path):
    path = tmp_path / "grype.json"
    path.write_text(json.dumps({"matches": [{
        "vulnerability": {"id": "CVE-2024-1234", "severity": "High",
                          "description": "A package issue", "fix": {"versions": ["2.0"]}},
        "artifact": {"name": "demo", "version": "1.0"},
    }]}), encoding="utf-8")
    finding = GrypeParser().parse(str(path))[0]
    assert finding.title == "CVE-2024-1234 in demo"
    assert finding.severity == "High"
    assert finding.remediation == "2.0"


def test_grype_fixture_reads_cvss_and_target():
    path = __import__("pathlib").Path(__file__).parent / "fixtures" / "grype.json"
    findings = GrypeParser().parse(str(path))
    grpc = findings[0]
    assert grpc.title == "CVE-2023-44487 in google.golang.org/grpc"
    assert grpc.cvss_score == 7.5
    assert grpc.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    assert grpc.remediation == "1.58.3"
    assert grpc.hosts[0].hostname == "alpine:3.18"
    assert findings[1].severity == "Info"  # Grype Negligible
    assert findings[1].cvss_score is None
