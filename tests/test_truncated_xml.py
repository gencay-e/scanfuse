import json

import pytest
from typer.testing import CliRunner

from scanfuse.cli import app
from scanfuse.engine import ScanfuseEngine
from scanfuse.parsers.base import PartialImportError

SCANS = [
    ("nikto", '<niktoscan><scandetails targetip="192.0.2.1"><item id="1"><description>Retained finding</description></item>', '</scandetails></niktoscan>'),
    ("burp", '<issues><issue><name>Retained finding</name></issue>', '</issues>'),
    ("nessus", '<NessusClientData_v2><Report><ReportHost name="192.0.2.1">'
     '<ReportItem pluginName="Retained finding"/></ReportHost></Report>', '</NessusClientData_v2>'),
    ("zap", '<OWASPZAPReport><site host="192.0.2.1" port="80"><alerts><alertitem>'
     '<alert>Retained finding</alert></alertitem></alerts></site>', '</OWASPZAPReport>'),
    ("nmap", '<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports>'
     '<port protocol="tcp" portid="80"><state state="open"/></port></ports></host>', '</nmaprun>'),
]


@pytest.mark.parametrize("format_name,body,closing", SCANS)
def test_truncated_xml_preserves_completed_records(tmp_path, format_name, body, closing):
    source = tmp_path / "scan.xml"
    source.write_text(body + closing, encoding="utf-8")
    engine = ScanfuseEngine(str(tmp_path / "unused"))
    expected = engine.process_file(str(source), format_name)
    assert len(expected) == 1
    source.write_text(body + "<broken", encoding="utf-8")
    with pytest.raises(PartialImportError, match="Invalid (Nikto )?XML") as error:
        engine.process_file(str(source), format_name)
    assert error.value.findings == expected

    baseline = tmp_path / "baseline.json"
    missing = expected[0].model_copy(update={"title": "Absent finding"})
    baseline.write_text(json.dumps({
        "schema_version": 2, "complete": True, "findings": [missing.model_dump()],
    }), encoding="utf-8")
    output = tmp_path / "report"
    result = CliRunner().invoke(app, [str(source), "-f", format_name,
                                    "--baseline", str(baseline), "--format-out", "json", "-o", str(output)])
    assert result.exit_code == 1
    report = json.loads((output / "report.json").read_text(encoding="utf-8"))
    assert report["complete"] is False
    assert len(report["errors"]) == 1
    assert len(report["findings"]) == 1
    assert report["findings"][0]["title"] == expected[0].title
    assert report["resolved"] == []
