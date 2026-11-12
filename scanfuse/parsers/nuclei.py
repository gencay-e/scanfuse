import json
import math
from urllib.parse import urlsplit

from pydantic import ValidationError

from scanfuse.models import Evidence, Finding, Host, Observation, host_key
from scanfuse.parsers.base import (
    BaseParser,
    PartialImportError,
    clean_ids,
    cve_ids,
    cwe_id,
    extract_urls,
)


class NucleiParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        findings = []
        invalid_lines: list[int] = []

        with open(file_path, encoding="utf-8-sig") as f:
            for line_idx, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                    if not self._looks_like_nuclei(data):
                        continue
                    findings.append(self._parse_dict(data))
                except (json.JSONDecodeError, ValidationError, ValueError, TypeError, AttributeError):
                    invalid_lines.append(line_idx)

        if not findings or invalid_lines:
            # Fallback: maybe it's a JSON array instead of JSONL
            with open(file_path, encoding="utf-8-sig") as f:
                try:
                    data = json.load(f)
                    if isinstance(data, list):
                        findings = []
                        invalid_items = []
                        for index, item in enumerate(data, start=1):
                            if self._looks_like_nuclei(item):
                                try:
                                    findings.append(self._parse_dict(item))
                                except (ValidationError, ValueError, TypeError, AttributeError):
                                    invalid_items.append(index)
                        if findings and invalid_items:
                            raise PartialImportError(
                                f"Invalid Nuclei finding at array position {invalid_items[0]}",
                                findings,
                            )
                    elif self._looks_like_nuclei(data):
                        try:
                            findings = [self._parse_dict(data)]
                        except (ValidationError, ValueError, TypeError, AttributeError):
                            pass
                    invalid_lines = []
                except json.JSONDecodeError:
                    pass
            if not findings:
                raise ValueError("Not a valid Nuclei JSON/JSONL file. If this is another tool's output, set --format.")

        if invalid_lines:
            raise PartialImportError(f"Invalid JSON on line {invalid_lines[0]}", findings)

        return findings

    @staticmethod
    def _looks_like_nuclei(data: object) -> bool:
        """A Nuclei result has at least one of these keys. Other JSON objects are not findings."""
        return isinstance(data, dict) and any(
            key in data for key in ("template-id", "info", "matched-at")
        )

    def _parse_dict(self, data: dict) -> Finding:
        info = data.get("info")
        if not isinstance(info, dict):
            info = {}
        template_id = str(data.get("template-id") or "unknown")
        name = str(info.get("name") or template_id or "unknown")

        severity_raw = info.get("severity") or "info"
        if not isinstance(severity_raw, str):
            severity_raw = str(severity_raw)
        severity_raw = severity_raw.lower()

        # Map Nuclei severity to Finding severity model
        severity_map = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "unknown": "Info"
        }
        severity = severity_map.get(severity_raw, "Info")

        description = info.get("description") or f"Nuclei template {template_id} matched."
        remediation = info.get("remediation")
        if not isinstance(description, str):
            description = str(description)
        if remediation is not None and not isinstance(remediation, str):
            remediation = str(remediation)

        classification = info.get("classification")
        if not isinstance(classification, dict):
            classification = {}
        cvss_score_raw = classification.get("cvss-score")
        try:
            cvss_score = float(cvss_score_raw) if cvss_score_raw is not None else None
            if cvss_score is not None and (not math.isfinite(cvss_score) or cvss_score < 0.0 or cvss_score > 10.0):
                cvss_score = None
        except (ValueError, TypeError):
            cvss_score = None

        cvss_vector = classification.get("cvss-metrics")
        if not isinstance(cvss_vector, str):
            cvss_vector = None

        # Handle host extraction
        ip = data.get("ip")
        host_val = data.get("host")
        hostname = None

        # If ip is missing but host is an IP, we could try to guess,
        # but let's stick to using ip as ip and host as hostname if different.
        if not ip and host_val:
            ip = host_val
        elif host_val and ip and host_val != ip:
            hostname = host_val
        elif host_val and not ip:
            ip = host_val

        if not ip:
            ip = "unknown"

        host_model = Host(ip=ip, hostname=hostname)

        # Handle evidence
        evidence_list = []
        req = data.get("request")
        resp = data.get("response")
        matched_at = data.get("matched-at")

        if req or resp:
            ev_text = ""
            if req:
                ev_text += f"Request:\n{req}\n"
            if resp:
                ev_text += f"\nResponse:\n{resp}"
            evidence_list.append(Evidence(type="http-request", data=ev_text.strip()))
        elif matched_at:
            evidence_list.append(Evidence(type="match", data=f"Matched at: {matched_at}"))

        cwe_raw = classification.get("cwe-id")
        cwes = [cwe_id(c) for c in cwe_raw] if isinstance(cwe_raw, list) else [cwe_id(cwe_raw)]
        identifiers = clean_ids(
            f"nuclei-template:{template_id}" if data.get("template-id") else None,
            cve_ids(classification.get("cve-id")),
            cwes,
        )

        # Web templates match at a URL; network templates match at host:port, which has no path.
        location = None
        if isinstance(matched_at, str) and matched_at.lower().startswith(("http://", "https://")):
            try:
                location = urlsplit(matched_at.strip()).path or "/"
            except ValueError:
                location = None

        return Finding(
            title=name,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            description=description,
            remediation=remediation,
            hosts=[host_model],
            observations=[Observation(host=host_key(host_model), location=location, source_tool="nuclei")],
            evidence=evidence_list,
            identifiers=identifiers,
            references=extract_urls(info.get("reference")),
            source_tool="nuclei"
        )
