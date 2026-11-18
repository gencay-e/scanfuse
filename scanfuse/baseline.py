"""Compare reports using the same identity as finding deduplication."""
import json
from collections.abc import Callable
from pathlib import Path

from scanfuse.models import Finding
from scanfuse.utils import _explicit_tool_ids, _identity, _local_ids, has_surrogates


def _compatible_findings(a: Finding, b: Finding) -> bool:
    map_a, map_b = _explicit_tool_ids(a), _explicit_tool_ids(b)
    for tool in map_a.keys() & map_b.keys():
        if map_a[tool] != map_b[tool]:
            return False
    ids_a, ids_b = _local_ids(a), _local_ids(b)
    return all(ids_a[prefix] == ids_b[prefix] for prefix in ids_a.keys() & ids_b.keys())


def compare_baseline(
    findings: list[Finding], path: Path, *, complete: bool = True,
    filter_previous: Callable[[list[Finding]], list[Finding]] | None = None,
) -> list[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except RecursionError as exc:
        raise ValueError("baseline JSON nesting is too deep") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 2:
        raise ValueError("baseline must be a schema_version 2 report")
    if data.get("complete") is not True:
        raise ValueError("baseline report must be complete")
    if not isinstance(data.get("findings"), list):
        raise ValueError("baseline findings must be a list")
    previous = [Finding.model_validate(item) for item in data["findings"]]
    if any(has_surrogates(finding.model_dump()) for finding in previous):
        raise ValueError("baseline contains findings with invalid Unicode surrogates")
    if filter_previous is not None:
        previous = filter_previous(previous)

    before_by_id: dict[object, list[Finding]] = {}
    for prev in previous:
        before_by_id.setdefault(_identity(prev), []).append(prev)
    current_by_id: dict[object, list[Finding]] = {}
    for curr in findings:
        current_by_id.setdefault(_identity(curr), []).append(curr)

    for finding in findings:
        matched = any(_compatible_findings(finding, prev) for prev in before_by_id.get(_identity(finding), ()))
        finding.status = "unchanged" if matched else "new"
    if not complete:
        return []
    resolved = []
    for finding in previous:
        if not any(_compatible_findings(finding, curr) for curr in current_by_id.get(_identity(finding), ())):
            finding.status = "resolved"
            resolved.append(finding)
    return resolved
