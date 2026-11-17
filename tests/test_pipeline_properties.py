"""Property tests for merge order and end-to-end report safety."""

from __future__ import annotations

import csv
import itertools
import json
import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st
from pypdf import PdfReader

from scanfuse.baseline import compare_baseline
from scanfuse.config import apply_overrides
from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Evidence, Finding, Host
from scanfuse.utils import deduplicate_findings

VECTORS = (
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
)
_safe_text = st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=25).filter(
    lambda value: bool(value.strip())
)


@given(
    descriptions=st.lists(_safe_text, min_size=3, max_size=3),
    vectors=st.lists(st.sampled_from(VECTORS), min_size=3, max_size=3),
    codes=st.lists(_safe_text, min_size=3, max_size=3),
)
@settings(max_examples=35, deadline=None)
def test_merge_semantics_do_not_depend_on_source_order(
    descriptions: list[str], vectors: list[str], codes: list[str]
) -> None:
    findings = [
        Finding(
            title="Shared issue", severity="High", cvss_score=8.0, cvss_vector=vectors[index],
            description=descriptions[index], remediation=descriptions[2-index], source_tool="alpha" if index < 2 else "beta",
            identifiers=["CVE-2025-1234", f"alpha-rule:local-{index}" if index < 2 else "beta-rule:local-2"],
            hosts=[Host(ip="192.0.2.10")],
            evidence=[Evidence(type="response", data=f"body-{index}", code=codes[index])],
        )
        for index in range(3)
    ]
    original = [finding.model_dump() for finding in findings]

    merged = [deduplicate_findings(list(order)) for order in itertools.permutations(findings)]

    def semantic(groups: list[Finding]) -> frozenset[tuple[object, ...]]:
        return frozenset(
            (
                frozenset(f.source_tool.split(", ")),
                frozenset(f.identifiers),
                frozenset((host.ip, host.hostname, host.os, host.port) for host in f.hosts),
                frozenset((e.type, e.data, e.code) for e in f.evidence),
                frozenset(
                    (
                        s.source_tool, s.title, s.severity, s.cvss_score, s.cvss_vector,
                        s.description, s.remediation, tuple(s.identifiers), s.port,
                    )
                    for s in f.sources
                ) if f.sources else frozenset(
                    ((f.source_tool, f.title, f.severity, f.cvss_score, f.cvss_vector,
                      f.description, f.remediation, tuple(f.identifiers), f.port),)
                ),
                f.severity,
                f.cvss_score,
                f.cvss_vector,
                f.description,
                f.remediation,
                f.cvss_merge_conflict,
            )
            for f in groups
        )

    assert all(semantic(result) == semantic(merged[0]) for result in merged[1:])
    assert len(merged[0]) == 2
    assert frozenset(
        (e.type, e.data, e.code) for group in merged[0] for e in group.evidence
    ) == frozenset(("response", f"body-{i}", codes[i]) for i in range(3))
    actual_descriptions = {
        source.description if group.sources else group.description
        for group in merged[0]
        for source in (group.sources or [group])
    }
    assert actual_descriptions == frozenset(descriptions)
    assert all(group.cvss_score == 8.0 and group.cvss_vector in VECTORS for group in merged[0])
    assert [finding.model_dump() for finding in findings] == original


@given(
    tool_ids=st.lists(
        st.tuples(st.sampled_from(("alpha", "beta", "gamma")), _safe_text),
        min_size=2,
        max_size=5,
    )
)
@settings(max_examples=12, deadline=None)
def test_generated_local_id_groups_are_permutation_invariant(
    tool_ids: list[tuple[str, str]],
) -> None:
    findings = [
        Finding(
            title="Shared issue", severity="Medium", description=f"record-{index}",
            source_tool=tool, identifiers=["CVE-2025-1234", f"{tool}-rule:{local_id}"],
            hosts=[Host(ip="192.0.2.10")],
            evidence=[Evidence(type="response", data=f"body-{index}", code=f"line-{index}")],
        )
        for index, (tool, local_id) in enumerate(tool_ids)
    ]

    def memberships(items: tuple[Finding, ...]) -> frozenset[frozenset[str]]:
        return frozenset(
            frozenset(e.data for e in group.evidence)
            for group in deduplicate_findings(list(items))
        )

    expected = memberships(tuple(findings))
    for order in itertools.permutations(findings):
        assert memberships(order) == expected


@given(
    title=_safe_text,
    description=_safe_text,
    payload=_safe_text,
    formula=st.sampled_from(["=1+1", "+SUM(A1:A2)", "-2+3", "@SUM(A1)", "\uFF1D1+1"]),
)
@settings(max_examples=15, deadline=None)
def test_active_downgraded_finding_stays_open_and_all_exports_are_safe(
    title: str, description: str, payload: str, formula: str
) -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        _exercise_pipeline(Path(temp_dir), title, description, payload, formula)


def _exercise_pipeline(tmp_path: Path, title: str, description: str, payload: str, formula: str) -> None:
    previous = Finding(
        title=title, severity="High", description=description, source_tool="scanner",
        identifiers=["scanner-rule:stable"], hosts=[Host(ip="192.0.2.20")],
    )
    baseline_dir = tmp_path / "baseline"
    ScanfuseEngine(str(baseline_dir)).export_json([previous])
    baseline_path = baseline_dir / "report.json"

    current = Finding.model_validate(previous.model_dump())
    current.severity = "Info"
    engine = ScanfuseEngine(str(tmp_path / "exports"))
    selected = engine.filter_by_host([current], "192.0.2.20")
    deduplicated = deduplicate_findings(selected)
    downgraded = apply_overrides(
        deduplicated, {"overrides": [{"tool_id": "scanner-rule:stable", "severity": "Info"}]}
    )
    resolved = compare_baseline(downgraded, baseline_path)
    engine.resolved = resolved
    assert engine.filter_findings(downgraded, min_severity="High") == []
    assert resolved == []
    visible = engine.filter_findings(downgraded, min_severity="Info")
    assert len(visible) == 1 and visible[0].status == "unchanged"

    visible[0].evidence = [
        Evidence(type="payload", data="<script>alert(1)</script>\n```\n" + payload, code="line <unsafe>")
    ]
    visible[0].description = formula
    engine.export_findings(visible)
    engine.export_json(visible)
    engine.export_csv(visible)
    engine.export_sarif(visible)
    engine.export_pdf(visible)

    report_html = (engine.output_dir / "report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in report_html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report_html
    assert "&amp;lt;" not in report_html

    report_json = json.loads((engine.output_dir / "report.json").read_text(encoding="utf-8"))
    assert report_json["findings"][0]["status"] == "unchanged"
    with (engine.output_dir / "report.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["Description"].startswith("'")
    sarif = json.loads((engine.output_dir / "report.sarif").read_text(encoding="utf-8"))
    assert len(sarif["runs"][0]["results"]) == 1
    assert len(PdfReader(engine.output_dir / "report.pdf").pages) >= 1
