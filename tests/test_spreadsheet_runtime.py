import os
import subprocess
from pathlib import Path

import pytest

from scanfuse.engine import ScanfuseEngine
from scanfuse.models import Finding


def _excel_available() -> bool:
    if os.name != "nt":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"Excel.Application\CLSID"):
            return True
    except FileNotFoundError:
        return False


@pytest.mark.skipif(not _excel_available(), reason="Requires installed Windows Excel COM")
def test_excel_import_does_not_execute_formulas(tmp_path):
    payloads = ["=1+1", "+1+1", "-1+1", "@SUM(1,1)", "＝1+1", "\t=1+1", "\n=1+1", " =1+1", "\u00a0=1+1"]
    ScanfuseEngine(str(tmp_path)).export_csv([
        Finding(title=value, severity="High", description=value, source_tool="test")
        for value in payloads
    ])
    script = Path(__file__).with_name("verify_spreadsheet.ps1")
    result = subprocess.run(  # noqa: S603, S607 - fixed local verification script
        ["pwsh", "-NoProfile", "-File", str(script), str(tmp_path / "report.csv"), str(len(payloads))],  # noqa: S607 - PowerShell on PATH
        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout
