"""Compare reports using the same identity as finding deduplication."""
import json
from pathlib import Path

from scanfuse.models import Finding
from scanfuse.utils import _identity, _local_ids


def compare_baseline(findings: list[Finding], path: Path, *, complete: bool = True) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 2:
        raise ValueError("baseline must be a schema_version 2 report")
    if data.get("complete") is not True:
        raise ValueError("baseline report must be complete")
    if not isinstance(data.get("findings"), list):
        raise ValueError("baseline findings must be a list")
    previous = [Finding.model_validate(item) for item in data["findings"]]
    def identity(f: Finding) -> tuple[object, ...]:
        tool_ids = tuple(sorted((key, tuple(sorted(values))) for key, values in _local_ids(f).items()))
        return (_identity(f), tool_ids)

    before = {identity(f) for f in previous}
    current = {identity(f) for f in findings}
    for finding in findings:
        finding.status = "unchanged" if identity(finding) in before else "new"
    if not complete:
        return []
    resolved = []
    for finding in previous:
        if identity(finding) not in current:
            finding.status = "resolved"
            resolved.append(finding)
    return resolved
