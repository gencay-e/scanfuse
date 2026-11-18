import json

import pytest
from typer.testing import CliRunner

from scanfuse.cli import app
from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Finding, Host, Observation
from scanfuse.parsers.base import PartialImportError
from scanfuse.parsers.sarif import SarifParser
from scanfuse.utils import deduplicate_findings


def _sarif() -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Semgrep", "rules": [{
                "id": "python.lang.security.audit.eval-detected",
                "name": "Dangerous eval",
                "help": {"text": "Avoid eval.", "markdown": "Avoid eval."},
                "helpUri": "https://example.test/rule",
                "properties": {"security-severity": "8.0"},
            }]}},
            "results": [{
                "ruleId": "python.lang.security.audit.eval-detected",
                "level": "error",
                "message": {"text": "eval() was detected"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "https://192.0.2.10/app.py"},
                    "region": {"startLine": 12},
                }}],
            }],
        }],
    }


def test_sarif_parser_maps_rule_result_and_location(tmp_path):
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(_sarif()), encoding="utf-8")
    finding = SarifParser().parse(str(path))[0]
    assert finding.title == "Dangerous eval"
    assert "eval() was detected" in finding.description
    assert finding.severity == "High"
    assert finding.source_tool == "Semgrep"
    assert finding.hosts[0].ip == "192.0.2.10"
    assert finding.evidence[0].data.endswith(":12")
    assert finding.references == ["https://example.test/rule"]


def test_sarif_explicit_format_and_export(tmp_path):
    source = tmp_path / "scan.sarif"
    source.write_text(json.dumps(_sarif()), encoding="utf-8")
    output = tmp_path / "report"
    findings = ScanfuseEngine(str(output)).process_file(str(source), "sarif")
    ScanfuseEngine(str(output)).export_sarif(findings)
    exported = json.loads((output / "report.sarif").read_text(encoding="utf-8"))
    assert exported["version"] == "2.1.0"
    assert exported["runs"][0]["results"][0]["ruleId"] == findings[0].identifiers[0]


def test_cli_accepts_sarif_output(tmp_path):
    source = tmp_path / "scan.sarif"
    source.write_text(json.dumps(_sarif()), encoding="utf-8")
    result = CliRunner().invoke(app, [str(source), "--format", "sarif",
                                      "--format-out", "sarif", "-o", str(tmp_path / "out")])
    assert result.exit_code == 0, result.stdout
    assert (tmp_path / "out" / "report.sarif").exists()


def test_sarif_markdown_title_and_rule_collisions_are_preserved(tmp_path):
    data = _sarif()
    data["runs"][0]["results"][0]["message"] = {"markdown": "**markdown title**"}
    data["runs"][0]["results"].append({
        "message": {"text": "second"},
        "locations": [],
    })
    source = tmp_path / "scan.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")
    findings = SarifParser().parse(str(source))
    assert findings[0].title == "Dangerous eval"
    assert "**markdown title**" in findings[0].description
    assert findings[1].title == "second"
    output = tmp_path / "report"
    ScanfuseEngine(str(output)).export_sarif(findings)
    exported = json.loads((output / "report.sarif").read_text(encoding="utf-8"))
    rule_ids = [result["ruleId"] for result in exported["runs"][0]["results"]]
    assert len(rule_ids) == len(set(rule_ids))
    assert exported["runs"][0]["results"][0]["properties"]["references"]


def test_sarif_export_preserves_description_and_all_references(tmp_path):
    finding = Finding(
        title="Title", severity="Low", description="Long description",
        remediation="Fix it", source_tool="test", identifiers=["CWE-79"],
        references=["https://example.test/a", "https://example.test/b"],
    )
    output = tmp_path / "report"
    ScanfuseEngine(str(output)).export_sarif([finding])
    data = json.loads((output / "report.sarif").read_text(encoding="utf-8"))
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["fullDescription"]["text"] == "Long description"
    assert rule["properties"]["references"] == finding.references


def test_sarif_handles_null_snippet_properties_and_rule_index(tmp_path):
    data = _sarif()
    run = data["runs"][0]
    run["tool"]["driver"]["rules"][0]["defaultConfiguration"] = {"level": "error"}
    run["tool"]["driver"]["rules"][0]["properties"]["cvss"] = {"vector": 42}
    result = run["results"][0]
    result.pop("ruleId")
    result["ruleIndex"] = 0
    result["properties"] = None
    result["locations"][0]["physicalLocation"]["region"]["snippet"] = None
    source = tmp_path / "nulls.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")

    finding = SarifParser().parse(str(source))[0]
    assert finding.title == "Dangerous eval"
    assert finding.severity == "High"
    assert finding.cvss_vector is None
    assert finding.evidence[0].code == ""
    assert finding.observations[0].host == "192.0.2.10"


def test_sarif_uses_each_run_tool_name(tmp_path):
    data = _sarif()
    second = json.loads(json.dumps(data["runs"][0]))
    second["tool"]["driver"]["name"] = "CodeQL"
    second["results"][0]["locations"] = []
    data["runs"].append(second)
    source = tmp_path / "multi.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")

    findings = SarifParser().parse(str(source))
    assert [finding.source_tool for finding in findings] == ["Semgrep", "CodeQL"]


def test_sarif_uses_default_level_and_markdown_help(tmp_path):
    data = _sarif()
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    rule["help"] = {"markdown": "See https://docs.example.test/fix"}
    rule["defaultConfiguration"] = {"level": "note"}
    rule["properties"] = {}
    data["runs"][0]["results"][0]["level"] = None
    source = tmp_path / "markdown.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")

    finding = SarifParser().parse(str(source))[0]
    assert finding.severity == "Low"
    assert finding.remediation == "See https://docs.example.test/fix"
    assert "https://docs.example.test/fix" in finding.references


def test_sarif_export_structure_follows_the_2_1_0_schema_for_locations(tmp_path):
    # The log was also checked against the official sarif-schema-2.1.0.json by hand;
    # the schema is not part of the package, so this checks the shape that matters.
    finding = Finding(
        title="T", severity="High", description="d", source_tool="zap", identifiers=["CWE-79"],
        hosts=[Host(ip="10.0.0.1", hostname="a.test"), Host(ip="unknown", hostname="b.test")],
        observations=[Observation(host="10.0.0.1", method="GET", location="/x", source_tool="zap")],
    )
    output = tmp_path / "report"
    ScanfuseEngine(str(output)).export_sarif([finding])
    data = json.loads((output / "report.sarif").read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0" and data["$schema"].endswith("sarif-2.1.0.json")
    (result,) = data["runs"][0]["results"]
    assert result["ruleId"] == "CWE-79" and result["message"]["text"] == "T"
    assert result["locations"] == [
        {"logicalLocations": [{"name": "10.0.0.1 (a.test)", "kind": "resource"}]},
        {"logicalLocations": [{"name": "b.test", "kind": "resource"}]},
    ]
    assert result["properties"]["observations"][0]["location"] == "/x"


def test_sarif_resolves_uri_bases_before_merging(tmp_path):
    findings = []
    for name in ["project-a", "project-b"]:
        data = _sarif()
        run = data["runs"][0]
        run["originalUriBaseIds"] = {
            "ROOT": {"uri": f"file:///{name}/"},
            "SRC": {"uri": "src/", "uriBaseId": "ROOT"},
        }
        run["artifacts"] = [{"location": {"uri": "main.py", "uriBaseId": "SRC"}}]
        run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}
        source = tmp_path / f"{name}.sarif"
        source.write_text(json.dumps(data), encoding="utf-8")
        finding = SarifParser().parse(str(source))[0]
        expected = f"file:///{name}/src/main.py:12"
        assert finding.observations[0].location == expected
        assert finding.evidence[0].data == expected
        findings.append(finding)
    assert len(deduplicate_findings(findings)) == 2


def test_sarif_preserves_plain_text_in_all_message_fields(tmp_path):
    data = _sarif()
    rule = data["runs"][0]["tool"]["driver"]["rules"][0]
    rule["shortDescription"] = {"text": "Use List<T> &amp; keep entities"}
    rule["fullDescription"] = {"text": "Literal <img src=x>"}
    rule["help"] = {"text": "Return Map<K,V> &lt;value&gt;"}
    data["runs"][0]["results"][0]["message"] = {"text": "Compare List<T> and x < y."}
    source = tmp_path / "literal.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")
    finding = SarifParser().parse(str(source))[0]
    assert finding.title == "Use List<T> &amp; keep entities"
    assert finding.description == "Compare List<T> and x < y.\n\nLiteral <img src=x>"
    assert finding.remediation == "Return Map<K,V> &lt;value&gt;"


@pytest.mark.parametrize("scope", ["rule", "global", "inline"])
def test_sarif_resolves_message_strings_and_arguments(tmp_path, scope):
    data = _sarif()
    driver = data["runs"][0]["tool"]["driver"]
    template = "Unsafe {0}: {{literal}} {1}; repeat {0}"
    driver["rules"][0]["messageStrings"] = {"unsafe": {"text": template}}
    driver["globalMessageStrings"] = {"unsafe": {"text": template}}
    message = {"id": "unsafe", "arguments": ["eval", "{0}"]}
    if scope == "global":
        driver["rules"][0].pop("messageStrings")
    elif scope == "inline":
        message["text"] = template
        driver["rules"][0]["messageStrings"]["unsafe"]["text"] = "wrong"
    data["runs"][0]["results"][0]["message"] = message
    source = tmp_path / "messages.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")
    finding = SarifParser().parse(str(source))[0]
    assert finding.description == "Unsafe eval: {literal} {0}; repeat eval"


def test_sarif_keeps_unresolved_uri_base_identity(tmp_path):
    data = _sarif()
    result = data["runs"][0]["results"][0]
    result["locations"][0]["physicalLocation"]["artifactLocation"] = {
        "uri": "main.py", "uriBaseId": "%SRCROOT%",
    }
    source = tmp_path / "unresolved.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")
    finding = SarifParser().parse(str(source))[0]
    assert "%SRCROOT%" in finding.observations[0].location
    assert "main.py:12" in finding.observations[0].location


def test_sarif_cyclic_uri_bases_report_partial_import(tmp_path):
    data = _sarif()
    run = data["runs"][0]
    run["originalUriBaseIds"] = {
        "A": {"uri": "a/", "uriBaseId": "B"},
        "B": {"uri": "b/", "uriBaseId": "A"},
    }
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {
        "uri": "main.py", "uriBaseId": "A",
    }
    source = tmp_path / "cyclic.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PartialImportError, match="[Cc]yclic") as exc:
        SarifParser().parse(str(source))
    assert len(exc.value.findings) == 1


@pytest.mark.parametrize("message", [
    {"id": "missing"},
    {"id": "\ud800"},
    {"text": "Missing {1}", "arguments": ["only-zero"]},
    {"text": "Bad {0}", "arguments": None},
])
def test_sarif_invalid_messages_preserve_other_results(tmp_path, message):
    data = _sarif()
    run = data["runs"][0]
    run["results"].append({"ruleId": "bad", "message": message})
    source = tmp_path / "invalid-message.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PartialImportError) as exc:
        SarifParser().parse(str(source))
    str(exc.value).encode("utf-8")
    assert len(exc.value.findings) >= 1
    assert exc.value.findings[0].title == "Dangerous eval"


@pytest.mark.parametrize("relative, expected", [
    ("../main.py", "file:///project/main.py:12"),
    ("../../main.py", "file:///main.py:12"),
    ("/main.py", "file:///main.py:12"),
])
def test_sarif_resolves_relative_paths_after_base_chain(tmp_path, relative, expected):
    data = _sarif()
    run = data["runs"][0]
    run["originalUriBaseIds"] = {
        "ROOT": {"uri": "file:///project/"},
        "SRC": {"uri": "src/", "uriBaseId": "ROOT"},
    }
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {
        "uri": relative, "uriBaseId": "SRC",
    }
    source = tmp_path / "parent-path.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")
    assert SarifParser().parse(str(source))[0].observations[0].location == expected


def test_sarif_literal_payload_survives_import_without_active_html(tmp_path):
    from html.parser import HTMLParser

    class Elements(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = []
            self.attributes = []

        def handle_starttag(self, tag, attrs):
            self.tags.append(tag)
            self.attributes.extend(attrs)

    data = _sarif()
    payload = 'List<T> <script>alert(1)</script><img src=x onerror="alert(2)">'
    data["runs"][0]["results"][0]["message"] = {"text": payload}
    source = tmp_path / "payload.sarif"
    source.write_text(json.dumps(data), encoding="utf-8")
    output = tmp_path / "out"
    engine = ScanfuseEngine(str(output))
    findings = engine.process_file(str(source), "auto")
    engine.export_findings(findings)
    engine.export_json(findings)
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert exported["findings"][0]["description"] == payload
    html = (output / "report.html").read_text(encoding="utf-8")
    parsed = Elements()
    parsed.feed(html)
    assert parsed.tags.count("script") == 1
    assert "img" not in parsed.tags
    assert not any(key.startswith("on") for key, _ in parsed.attributes)
    assert "List&lt;T&gt;" in html


@pytest.mark.parametrize("title", ["Unsafe {0}", "Literal {{value}}", "Unmatched { and }"])
def test_sarif_export_preserves_literal_message_braces(tmp_path, title):
    finding = Finding(title=title, severity="High", description="Details", source_tool="scanner")
    ScanfuseEngine(str(tmp_path)).export_sarif([finding])
    parsed = SarifParser().parse(str(tmp_path / "report.sarif"))
    assert parsed == [finding]
    path = tmp_path / "report.sarif"
    data = json.loads(path.read_text(encoding="utf-8"))
    del data["runs"][0]["results"][0]["properties"]["scanfuse-finding-version"]
    path.write_text(json.dumps(data), encoding="utf-8")
    parsed = SarifParser().parse(str(path))
    assert parsed[0].title == title
    assert parsed[0].description == f"{title}\n\nDetails"


def test_sarif_roundtrip_preserves_complete_finding_and_retest_identity(tmp_path):
    from scanfuse.baseline import compare_baseline
    from scanfuse.models import Evidence, SourceRecord

    finding = Finding(
        title="Title {0}", severity="High", description="Full description", remediation="Fix",
        source_tool="nuclei", identifiers=["CVE-2026-12345", "nuclei-template:abc"],
        port="443/tcp", cvss_score=8.0, cvss_vector="CVSS:3.1/AV:N/AC:L",
        hosts=[Host(ip="192.0.2.1", hostname="web.test")],
        observations=[Observation(host="192.0.2.1", method="GET", location="/x", source_tool="nuclei")],
        evidence=[Evidence(type="http", data="Response", code="snippet", source="nuclei", hosts=["192.0.2.1"])],
        references=["https://example.test/ref"], tags=["reviewed"], status="unchanged",
        sources=[SourceRecord(source_tool="nuclei", title="Original", severity="High", description="D",
                              identifiers=["nuclei-template:abc"])],
    )
    engine = ScanfuseEngine(str(tmp_path / "report"))
    engine.export_sarif([finding])
    restored = SarifParser().parse(str(tmp_path / "report" / "report.sarif"))
    assert restored == [finding]
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"schema_version": 2, "complete": True,
                                    "findings": [finding.model_dump()]}), encoding="utf-8")
    assert compare_baseline(restored, baseline) == []
    assert restored[0].status == "unchanged"


@pytest.mark.parametrize("field,value", [("hosts", None), ("observations", 7),
                                          ("cvss_score", 99), ("scanfuse-finding-version", 2)])
def test_invalid_sarif_roundtrip_record_preserves_valid_sibling(tmp_path, field, value):
    finding = Finding(title="Valid", severity="High", description="D", source_tool="test")
    ScanfuseEngine(str(tmp_path)).export_sarif([finding, finding])
    path = tmp_path / "report.sarif"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["runs"][0]["results"][1]["properties"][field] = value
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PartialImportError) as error:
        SarifParser().parse(str(path))
    assert error.value.findings == [finding]


@pytest.mark.parametrize("second_tool", ["nmap", "nuclei"])
def test_roundtrip_host_filter_recalculates_merged_summary(tmp_path, second_tool):
    from scanfuse.models import Host
    from scanfuse.utils import deduplicate_findings

    first = Finding(title="Shared issue", severity="High", description="Host one",
                    source_tool="nmap", hosts=[Host(ip="192.0.2.1")],
                    tags=["first"], references=["https://example.org/first"])
    second = Finding(title="Shared issue", severity="Low", description="Host two",
                     source_tool=second_tool, hosts=[Host(ip="192.0.2.2")],
                     tags=["second"], references=["https://example.org/second"])
    engine = ScanfuseEngine(str(tmp_path))
    engine.export_sarif(deduplicate_findings([first, second]))
    imported = engine.process_file(str(tmp_path / "report.sarif"), "auto")
    selected, = engine.filter_by_host(imported, "192.0.2.2")
    assert selected.severity == "Low"
    assert selected.description == "Host two"
    assert selected.source_tool == second_tool
    assert selected.tags == ["second"]
    assert selected.references == second.references
    assert len(selected.sources) == 1
    assert selected.sources[0].description == "Host two"


def test_roundtrip_host_filter_keeps_alias_sources_and_override_tags(tmp_path):
    from scanfuse.config import apply_overrides
    from scanfuse.models import Host
    from scanfuse.utils import deduplicate_findings

    findings = [
        Finding(title="Shared issue", severity="High", description="IP only",
                source_tool="nmap", hosts=[Host(ip="192.0.2.1")], tags=["ip"]),
        Finding(title="Shared issue", severity="Low", description="IP and name",
                source_tool="nmap", hosts=[Host(ip="192.0.2.1", hostname="node.example")], tags=["name"]),
        Finding(title="Shared issue", severity="Critical", description="Other host",
                source_tool="nmap", hosts=[Host(ip="192.0.2.2")], tags=["other"]),
    ]
    merged = deduplicate_findings(findings)
    overridden = apply_overrides(merged, {"overrides": [{"title": "Shared issue", "tags": ["custom"]}]})
    engine = ScanfuseEngine(str(tmp_path))
    engine.export_sarif(overridden)
    imported = engine.process_file(str(tmp_path / "report.sarif"), "auto")
    selected, = engine.filter_by_host(imported, "node.example")
    assert selected.severity == "High"
    assert selected.tags == ["custom", "ip", "name"]
    assert [source.description for source in selected.sources] == ["IP only", "IP and name"]
