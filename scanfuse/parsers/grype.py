import json
from pathlib import Path
from typing import Any

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import BaseParser, clean_ids, cve_ids, extract_urls


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class GrypeParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        try:
            data = json.loads(Path(file_path).read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid Grype/Syft JSON: {exc}") from exc
        payload: dict[str, Any] = data if isinstance(data, dict) else {}
        matches = payload.get("matches")
        if not isinstance(matches, list):
            raise ValueError("Not a valid Grype JSON report")
        findings: list[Finding] = []
        severity_map = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium",
                        "LOW": "Low", "NEGLIGIBLE": "Info", "UNKNOWN": "Info"}
        source_info = _dict(payload.get("source", payload.get("context", {}).get("source", {})))
        target = source_info.get("target")
        if isinstance(target, dict):
            target = target.get("userInput") or target.get("imageID") or target.get("path")
        target_name = str(target or source_info.get("name") or source_info.get("imageName") or "image")

        for match in matches:
            if not isinstance(match, dict):
                continue
            vulnerability = _dict(match.get("vulnerability"))
            artifact = _dict(match.get("artifact"))
            vuln_id = str(vulnerability.get("id") or "grype-vulnerability")
            package = str(artifact.get("name") or "unknown package")
            version = artifact.get("version")
            pkg_version = str(version) if version is not None else None
            severity = severity_map.get(str(vulnerability.get("severity") or "UNKNOWN").upper(), "Info")
            description = str(vulnerability.get("description") or f"{vuln_id} affects {package}")
            cve_list = cve_ids(vuln_id)
            cvss_val = vulnerability.get("cvss") or vulnerability.get("cvssData")
            cvss_vector = None
            cvss_score = None
            if isinstance(cvss_val, list):
                # Highest valid base score, with its own vector.
                for entry in cvss_val:
                    metrics = _dict(entry).get("metrics")
                    score = _dict(metrics).get("baseScore")
                    if isinstance(score, bool) or not isinstance(score, (int, float)):
                        continue
                    if 0.0 <= float(score) <= 10.0 and (cvss_score is None or float(score) > cvss_score):
                        cvss_score = float(score)
                        vector = _dict(entry).get("vector")
                        cvss_vector = str(vector) if vector else None
            elif isinstance(cvss_val, str):
                cvss_vector = cvss_val
            findings.append(Finding(
                title=f"{vuln_id} in {package}",
                severity=severity,
                description=description,
                remediation=str(_dict(vulnerability.get("fix")).get("versions", [None])[0])
                if _dict(vulnerability.get("fix")).get("versions") else None,
                hosts=[Host(ip="local", hostname=str(target_name))],
                evidence=[Evidence(type="package", data=f"{package} {pkg_version or ''}".strip())],
                source_tool="grype",
                identifiers=clean_ids(vuln_id, cve_list),
                references=extract_urls(vulnerability.get("urls")),
                cvss_vector=cvss_vector,
                cvss_score=cvss_score,
            ))
        return findings
