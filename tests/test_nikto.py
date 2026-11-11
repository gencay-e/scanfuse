import json

from scanfuse.parsers.nikto import NiktoParser


def test_nikto_json(tmp_path):
    path = tmp_path / "nikto.json"
    path.write_text(json.dumps({"vulnerabilities": [{
        "id": "OSVDB-1", "host": "192.0.2.5", "msg": "Directory listing",
        "severity": "medium",
    }]}), encoding="utf-8")
    finding = NiktoParser().parse(str(path))[0]
    assert finding.title == "Directory listing"
    assert finding.severity == "Medium"


FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures"


def test_nikto_json_host_list():
    # `nikto -Format json` writes a list of hosts, each with its vulnerabilities.
    findings = NiktoParser().parse(str(FIXTURES / "nikto.json"))
    assert len(findings) == 2
    assert findings[0].title.startswith("The anti-clickjacking X-Frame-Options header")
    assert findings[0].hosts[0].ip == "192.0.2.10"
    assert findings[0].port == "80"
    assert "999986" in findings[0].identifiers


def test_nikto_xml_reads_target_from_scandetails():
    finding = NiktoParser().parse(str(FIXTURES / "nikto.xml"))[0]
    assert finding.hosts[0].ip == "192.0.2.10"
    assert finding.hosts[0].hostname == "web.test"
    assert finding.port == "80"
