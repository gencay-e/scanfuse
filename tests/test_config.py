import pytest

from scanfuse.config import apply_overrides, validate_config
from scanfuse.models import Finding


def _finding(port="80/tcp"):
    return Finding(title="Rule", severity="High", description="d", source_tool="test", port=port)


def test_numeric_config_port_matches_port_with_protocol():
    assert apply_overrides([_finding()], {"exclusions": [{"port": 80}]}) == []


def test_exclusion_rejects_override_only_fields():
    for field, value in (("severity", "Low"), ("tags", ["accepted"])):
        with pytest.raises(ValueError, match="cannot use severity or tags"):
            validate_config({"exclusions": [{"title": "Rule", field: value}]})


def test_source_tool_override_is_order_independent_for_merged_findings():
    cfg = {"overrides": [{"source_tool": "zap*", "severity": "Low"}]}
    first = Finding(title="XSS", severity="High", description="d", source_tool="zap, burp")
    second = Finding(title="XSS", severity="High", description="d", source_tool="burp, zap")
    assert [f.severity for f in apply_overrides([first, second], cfg)] == ["Low", "Low"]
