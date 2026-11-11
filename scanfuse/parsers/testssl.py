import json
from pathlib import Path
from typing import Any

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import BaseParser, clean_ids


class TestsslParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        try:
            data = json.loads(Path(file_path).read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid testssl.sh JSON: {exc}") from exc

        if isinstance(data, list):
            items: list[Any] = data
        elif isinstance(data, dict):
            raw_items = data.get("scanResult", data.get("results", data.get("findResults", [])))
            items = raw_items if isinstance(raw_items, list) else []
        else:
            items = []

        if not isinstance(items, list):
            items = []
        items = _flatten_pretty(items)

        findings: list[Finding] = []
        severity_map = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "OK": "Info",
            "INFO": "Info",
        }

        for item in items:
            if not isinstance(item, dict):
                continue
            sev_raw = str(item.get("severity") or item.get("severityLevel") or item.get("findingSeverity") or "OK").upper()
            # OK/INFO/DEBUG are not findings. WARN marks a check testssl.sh could not run
            # completely (e.g. engine_problem) and is skipped; FATAL means the scan failed.
            if sev_raw in {"OK", "INFO", "DEBUG", "NONE", "WARN", "WARNING"}:
                continue
            if sev_raw == "FATAL":
                raise ValueError(f"testssl.sh scan failed: {item.get('finding') or item.get('id')}")
            severity = severity_map.get(sev_raw, "Info")
            id_ = str(item.get("id") or item.get("finding") or "testssl")
            finding_text = str(item.get("finding") or item.get("desc") or item.get("details") or "")
            title = id_
            description = finding_text or id_

            target_host = str(item.get("ip") or item.get("targetHost") or item.get("host") or "unknown")
            hostname = None
            ip = target_host
            if "/" in target_host:
                parts = target_host.split("/", 1)
                hostname = parts[0]
                ip = parts[1]

            port_val = item.get("port")
            try:
                port = int(port_val) if port_val is not None else None
            except (TypeError, ValueError):
                port = None

            cve_val = item.get("cve")
            cwe_val = item.get("cwe")
            identifiers = clean_ids(id_, cve_val, cwe_val)

            findings.append(Finding(
                title=title,
                severity=severity,
                description=description,
                hosts=[Host(ip=ip or "unknown", hostname=hostname, port=port)],
                evidence=[Evidence(type="tls", data=json.dumps(item))],
                source_tool="testssl.sh",
                identifiers=identifiers,
                port=str(port) if port is not None else None,
            ))
        return findings


def _flatten_pretty(items: list[Any]) -> list[Any]:
    """`--jsonfile-pretty` nests the checks per target: scanResult[].{protocols,ciphers,...}[].
    Each nested check gets the target's ip and port, so it looks like a `--jsonfile` line."""
    flat: list[Any] = []
    for entry in items:
        if not isinstance(entry, dict) or "targetHost" not in entry:
            flat.append(entry)
            continue
        target = entry.get("targetHost") or ""
        ip = entry.get("ip") or ""
        combined = f"{target}/{ip}" if target and ip and target != ip else (ip or target)
        for value in entry.values():
            if not isinstance(value, list):
                continue
            for check in value:
                if isinstance(check, dict) and "id" in check:
                    flat.append({"ip": combined, "port": entry.get("port"), **check})
    return flat
