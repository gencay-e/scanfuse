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
