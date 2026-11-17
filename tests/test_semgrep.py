import json
from pathlib import Path

from scanfuse.parsers.semgrep import SemgrepParser

FIXTURE = Path(__file__).parent / "fixtures" / "semgrep.json"


def test_semgrep_parser_maps_rule_severity_and_location():
    findings = SemgrepParser().parse(str(FIXTURE))
    eval_finding = findings[0]
    assert eval_finding.title == "Detected the use of eval()."
    assert eval_finding.severity == "Medium"  # Semgrep WARNING
    assert eval_finding.evidence[0].data == "app/main.py:12"
    assert "python.lang.security.audit.eval-detected.eval-detected" in eval_finding.identifiers
    assert findings[1].severity == "High"  # Semgrep ERROR

def test_semgrep_accepts_uppercase_severity_and_cwe_metadata(tmp_path):
    source = tmp_path / "semgrep.json"
    source.write_text(json.dumps({"results": [
        {"check_id": "rule", "extra": {"severity": "CRITICAL", "metadata": {"cwe": "CWE-79"}}},
        {"check_id": "rule", "extra": {"severity": "HIGH"}},
        {"check_id": "rule", "extra": {"severity": "LOW"}},
    ]}), encoding="utf-8")
    findings = SemgrepParser().parse(str(source))
    assert [finding.severity for finding in findings] == ["Critical", "High", "Low"]
    assert findings[0].identifiers == ["rule", "CWE-79"]
