import json
from pathlib import Path
from typing import Any

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import (
    BaseParser,
    PartialImportError,
    clean_ids,
    cve_ids,
    cwe_ids_from_text,
)


class TestsslParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        try:
            data = json.loads(Path(file_path).read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid testssl.sh JSON: {exc}") from exc

        if isinstance(data, list):
            items: list[Any] = data
        elif isinstance(data, dict):
            container_key = next((k for k in ("scanResult", "results", "findResults") if k in data), None)
            if container_key is not None:
                raw_items = data[container_key]
                if not isinstance(raw_items, list):
                    raise ValueError(f"Not a valid testssl.sh JSON report: '{container_key}' must be a list")
                items = raw_items
            elif any(key in data for key in ("id", "finding", "severity", "severityLevel", "findingSeverity")):
                items = [data]
            else:
                raise ValueError("Not a valid testssl.sh JSON report")
        else:
            raise ValueError("Not a valid testssl.sh JSON report")

        parse_errors: list[str] = []
        items = _flatten_pretty(items, parse_errors)

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
                parse_errors.append("testssl.sh entry must be an object")
                continue
            if not any(key in item for key in ("id", "finding")):
                parse_errors.append("testssl.sh entry must contain an id or finding")
                continue
            sev_raw = str(item.get("severity") or item.get("severityLevel") or item.get("findingSeverity") or "OK").upper()
            # OK/INFO/DEBUG are not findings. WARN marks a non-fatal OpenSSL check notice
            # (e.g. engine_problem) and is skipped; FATAL marks scan failure.
            if sev_raw in {"OK", "INFO", "DEBUG", "NONE", "WARN", "WARNING"}:
                continue
            if sev_raw == "FATAL":
                parse_errors.append(f"testssl.sh scan failed: {item.get('finding') or item.get('id')}")
                continue
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
            port_proto = None
            if isinstance(port_val, str) and "/" in port_val:
                port_val, port_proto = port_val.split("/", 1)
            try:
                port = int(port_val) if port_val is not None else None
            except OverflowError:
                parse_errors.append("testssl.sh port must be a finite number")
                continue
            except (TypeError, ValueError):
                port = None

            cve_val = item.get("cve")
            cwe_val = item.get("cwe")
            identifiers = clean_ids(id_, cve_ids(cve_val), cwe_ids_from_text(cwe_val))

            findings.append(Finding(
                title=title,
                severity=severity,
                description=description,
                hosts=[Host(ip=ip or "unknown", hostname=hostname, port=port)],
                evidence=[Evidence(type="tls", data=json.dumps(item))],
                source_tool="testssl.sh",
                identifiers=identifiers,
                port=f"{port}/{port_proto}" if port is not None and port_proto else (
                    str(port) if port is not None else None
                ),
            ))
        if parse_errors:
            message = "; ".join(parse_errors)
            if findings:
                raise PartialImportError(message, findings)
            raise ValueError(message)
        return findings


def _flatten_pretty(items: list[Any], parse_errors: list[str]) -> list[Any]:
    """`--jsonfile-pretty` nests the checks per target: scanResult[].{protocols,ciphers,...}[].
    Each nested check gets the target's ip and port, so it looks like a `--jsonfile` line."""
    flat: list[Any] = []
    for entry in items:
        if (
            not isinstance(entry, dict)
            or "targetHost" not in entry
            or any(key in entry for key in ("id", "finding", "severity", "severityLevel", "findingSeverity"))
        ):
            flat.append(entry)
            continue
        target = entry.get("targetHost") or ""
        ip = entry.get("ip") or ""
        combined = f"{target}/{ip}" if target and ip and target != ip else (ip or target)
        for key, value in entry.items():
            if not isinstance(value, list):
                if key in {"pretest", "protocols", "grease", "ciphers", "serverPreferences",
                           "serverDefaults", "headerResponse", "vulnerabilities", "cipherTests",
                           "browserSimulations"}:
                    parse_errors.append(f"testssl.sh category '{key}' must be a list")
                continue
            for check in value:
                if isinstance(check, dict) and "id" in check:
                    flat.append({"ip": combined, "port": entry.get("port"), **check})
                else:
                    parse_errors.append(f"testssl.sh category '{key}' entry must be an object with an id")
    return flat
