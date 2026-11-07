"""A moderately large input must be processed without losing hosts or evidence.

The full 100,000-finding check is `python tools/large_check.py 100000`. Set SCANFUSE_LARGE_COUNT to
run a different size here.
"""
import importlib.util
import os
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "large_check.py"


@pytest.mark.skipif(not TOOL.exists(), reason="tools/large_check.py is not part of this package")
@pytest.mark.parametrize("fmt", ["json", "csv", "markdown"])
def test_large_input_keeps_every_host_and_evidence(tmp_path, fmt):
    spec = importlib.util.spec_from_file_location("large_check", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    count = int(os.environ.get("SCANFUSE_LARGE_COUNT", "4000"))
    source = tmp_path / "input.jsonl"
    unique = module.generate(source, count)
    out = tmp_path / "out"
    _seconds, _peak, code, text = module.run_scanfuse(source, out, fmt)
    assert code == 0, text
    assert module.check(fmt, out, count, unique) == []
