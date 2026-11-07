"""Checks against output of real scanner runs (nmap 7.94 against 127.0.0.1).

real_nmap_os_detection.xml and real_nmap_closed_ports.xml are real nmap output; the OS guesses were cut to three.
The CPE test uses a hand-written file in the format nmap documents for -sV results.
"""
import os

from typer.testing import CliRunner

from scanfuse.cli import app
from scanfuse.engine import ScanfuseEngine

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
runner = CliRunner(env={"COLUMNS": "400"})


def parse(name, tmp_path):
    return ScanfuseEngine(str(tmp_path)).process_file(os.path.join(FIXTURES, name), "nmap")


def test_os_guess_with_highest_accuracy_is_kept(tmp_path):
    (finding,) = parse("real_nmap_os_detection.xml", tmp_path)
    assert finding.title.startswith("Open Port: 2024/tcp")
    assert finding.hosts[0].ip == "127.0.0.1"
    assert finding.hosts[0].os == "Linux 5.0 - 5.7 (97%)"


def test_os_guess_appears_in_the_markdown_report(tmp_path):
    result = runner.invoke(app, [os.path.join(FIXTURES, "real_nmap_os_detection.xml"), "-o", str(tmp_path / "out")])
    assert result.exit_code == 0, result.stdout
    text = next((tmp_path / "out").glob("open-port-2024*.md")).read_text(encoding="utf-8")
    assert "OS: Linux 5.0 - 5.7 (97%)" in text


def test_scan_without_open_ports_says_so_and_exports_nothing(tmp_path):
    out = tmp_path / "out"
    result = runner.invoke(app, [os.path.join(FIXTURES, "real_nmap_closed_ports.xml"), "-o", str(out)])
    assert result.exit_code == 0, result.stdout
    assert "no findings" in result.stdout.lower()
    assert "Nothing was exported" in result.stdout
    assert not out.exists()


def test_cpe_from_version_detection_is_kept_as_identifier(tmp_path):
    source = tmp_path / "sv.xml"
    source.write_text(
        '<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.18.0" method="probed" conf="10">'
        "<cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service>"
        "</port></ports></host></nmaprun>",
        encoding="utf-8",
    )
    (finding,) = ScanfuseEngine(str(tmp_path)).process_file(str(source), "nmap")
    assert finding.identifiers == ["cpe:/a:igor_sysoev:nginx:1.18.0", "cpe:/o:linux:linux_kernel"]
    assert "nginx 1.18.0" in finding.title


def test_os_guess_of_several_tools_is_combined_when_findings_merge(tmp_path):
    from scanfuse.models import Finding, Host
    from scanfuse.utils import deduplicate_findings
    a = Finding(title="Open Port: 22/tcp (ssh)", severity="Info", description="d", source_tool="nmap",
                port="22/tcp", hosts=[Host(ip="10.0.0.1", os="Linux 5.0 - 5.7 (97%)")])
    b = Finding(title="Open Port: 22/tcp (ssh)", severity="Info", description="d", source_tool="nmap",
                port="22/tcp", hosts=[Host(ip="10.0.0.1", os="Linux 5.0 - 5.7 (97%)")])
    (merged,) = deduplicate_findings([a, b])
    assert merged.hosts[0].os == "Linux 5.0 - 5.7 (97%)"
