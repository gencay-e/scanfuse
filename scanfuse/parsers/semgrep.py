import json
from pathlib import Path
from typing import Any

from scanfuse.models import Evidence, Finding, Host, Observation
from scanfuse.parsers.base import (
    BaseParser,
    PartialImportError,
    as_dict,
    clean_ids,
    cve_ids,
    cwe_ids_from_text,
    extract_urls,
)


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
        parse_errors: list[str] = []
        severity_map = {"CRITICAL": "Critical", "HIGH": "High", "ERROR": "High",
                        "MEDIUM": "Medium", "WARNING": "Medium", "LOW": "Low", "INFO": "Info"}
        for result in results:
            if not isinstance(result, dict):
                parse_errors.append("Semgrep result entry must be an object")
                continue
            extra = as_dict(result.get("extra"))
            metadata = as_dict(extra.get("metadata"))
            rule_id = str(result.get("check_id") or "semgrep-rule")
            start = as_dict(result.get("start"))
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
        raw_errors = payload.get("errors")
        if "errors" in payload and raw_errors is not None and not isinstance(raw_errors, list):
            if findings:
                raise PartialImportError("Semgrep 'errors' must be a list", findings)
            raise ValueError("Semgrep 'errors' must be a list")
        if isinstance(raw_errors, list) and raw_errors:
            first = raw_errors[0]
            if isinstance(first, dict):
                detail = str(first.get("message") or first.get("short_msg") or first.get("type") or "scan error").strip()
            else:
                detail = str(first).strip() or "scan error"
            parse_errors.append(f"Semgrep reported {len(raw_errors)} error(s): {detail}")
        if parse_errors:
            raise PartialImportError("; ".join(dict.fromkeys(parse_errors)), findings)
        return findings
