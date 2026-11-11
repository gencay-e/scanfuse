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
