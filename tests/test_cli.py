import json
import os

import pytest
from typer.testing import CliRunner

from scanfuse.cli import app

runner = CliRunner()

def test_cli_parse_nmap(tmp_path):
    output_dir = tmp_path / "report"
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "dummy_nmap_clean.xml")

    result = runner.invoke(app, [fixture_path, "-o", str(output_dir)])
    assert result.exit_code == 0
    assert "Found 2 findings" in result.stdout

    # Check that markdown files were created
    assert output_dir.exists()
    files = list(output_dir.glob("*.md"))
    assert len(files) == 3

    titles = [f.read_text(encoding="utf-8").split("\n")[0] for f in files]
    assert any("Open Port: 80/tcp" in t for t in titles)
    assert any("Open Port: 443/tcp" in t for t in titles)

def test_cli_parse_nuclei(tmp_path):
    output_dir = tmp_path / "report"
    fixture_path = os.path.join(os.path.dirname(__file__), "fixtures", "dummy_nuclei.json")

    result = runner.invoke(app, [fixture_path, "-o", str(output_dir)])
    assert result.exit_code == 0
    assert "Found 2 findings" in result.stdout

    files = list(output_dir.glob("*.md"))
    assert len(files) == 3

    titles = [f.read_text(encoding="utf-8").split("\n")[0] for f in files]
    assert any("Apache" in t for t in titles)
    assert any("Wappalyzer" in t for t in titles)


def _run_with_config(tmp_path, monkeypatch, config_text):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".scanfuse.yaml").write_text(config_text, encoding="utf-8")
    source = tmp_path / "scan.json"
    source.write_text(
        "\n".join(json.dumps({"info": {"name": t}}) for t in ["Ignored alert", "Retained alert"]),
        encoding="utf-8",
    )
    output = tmp_path / "report"
    result = runner.invoke(
        app, [str(source), "-f", "nuclei", "--format-out", "json", "-o", str(output)]
    )
    return result, output


@pytest.mark.parametrize(
    "config_text",
    [
        "ignore_titles: 5",
        "ignore_titles: true",
        "ignore_titles: {a: b}",
        "ignore_titles: [1, 2]",
        'ignore_titles: ["ok", 3]',
        "ignore_titles: [[x]]",
    ],
)
def test_config_ignore_titles_wrong_type_reports_error_and_exit_1(tmp_path, monkeypatch, config_text):
    result, output = _run_with_config(tmp_path, monkeypatch, config_text)
    assert result.exit_code == 1, result.stdout
    assert "ignore_titles must be a list of strings" in result.stdout
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))["findings"]
    assert [f["title"] for f in exported] == ["Ignored alert", "Retained alert"]


@pytest.mark.parametrize("config_text", ["- a\n- b", "just text", "42"])
def test_config_not_a_mapping_reports_error_and_exit_1(tmp_path, monkeypatch, config_text):
    result, _ = _run_with_config(tmp_path, monkeypatch, config_text)
    assert result.exit_code == 1, result.stdout
    assert "must contain a mapping" in result.stdout


def test_config_valid_list_applies_rules_and_exit_0(tmp_path, monkeypatch):
    result, output = _run_with_config(tmp_path, monkeypatch, 'ignore_titles: ["Ignored"]')
    assert result.exit_code == 0, result.stdout
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))["findings"]
    assert [f["title"] for f in exported] == ["Retained alert"]


@pytest.mark.parametrize("config_text", ["", "ignore_titles:", "other: 1"])
def test_config_empty_or_without_ignore_titles_is_ok(tmp_path, monkeypatch, config_text):
    result, output = _run_with_config(tmp_path, monkeypatch, config_text)
    assert result.exit_code == 0, result.stdout
    exported = json.loads((output / "report.json").read_text(encoding="utf-8"))["findings"]
    assert len(exported) == 2
