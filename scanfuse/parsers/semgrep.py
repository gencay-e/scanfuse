import json
from pathlib import Path
from typing import Any

from scanfuse.models import Evidence, Finding, Host, Observation
from scanfuse.parsers.base import BaseParser, clean_ids, cve_ids, cwe_ids_from_text, extract_urls


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class SemgrepParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        try:
            data = json.loads(Path(file_path).read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid Semgrep JSON: {exc}") from exc
        payload: dict[str, Any] = data if isinstance(data, dict) else {}
        results = payload.get("results")
        if not isinstance(results, list):
            raise ValueError("Not a valid Semgrep JSON report")
        findings: list[Finding] = []
        severity_map = {"CRITICAL": "Critical", "HIGH": "High", "ERROR": "High",
                        "MEDIUM": "Medium", "WARNING": "Medium", "LOW": "Low", "INFO": "Info"}
        for result in results:
            if not isinstance(result, dict):
                continue
            extra = _dict(result.get("extra"))
            metadata = _dict(extra.get("metadata"))
            rule_id = str(result.get("check_id") or "semgrep-rule")
            start = _dict(result.get("start"))
            path = str(result.get("path") or "unknown")
            line = start.get("line")
            message = str(extra.get("message") or rule_id)
            severity = severity_map.get(str(extra.get("severity") or "WARNING").upper(), "Medium")
            location = f"{path}:{line}" if line is not None else path
            findings.append(Finding(
                title=message,
                severity=severity,
                description=message,
                hosts=[Host(ip="local", hostname=path)],
                evidence=[Evidence(type="code-location", data=location)],
                source_tool="semgrep",
                observations=[Observation(location=location, source_tool="semgrep")],
                identifiers=clean_ids(rule_id, cve_ids(metadata.get("cve")),
                                     cwe_ids_from_text(metadata.get("cwe"))),
                references=extract_urls(metadata.get("references")),
            ))
        return findings
