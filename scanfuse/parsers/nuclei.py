import ipaddress
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
        try:
            return self._parse(file_path)
        except UnicodeDecodeError as exc:
            raise ValueError(f"Invalid Nuclei text encoding: {exc}") from exc

    def _parse(self, file_path: str) -> list[Finding]:
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
                        invalid_lines.append(line_idx)
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
                        if not data:
                            return []
                        findings = []
                        invalid_items = []
                        for index, item in enumerate(data, start=1):
                            if not self._looks_like_nuclei(item):
                                invalid_items.append(index)
                                continue
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
        except (ValueError, TypeError, OverflowError):
            cvss_score = None

        cvss_vector = classification.get("cvss-metrics")
        if not isinstance(cvss_vector, str):
            cvss_vector = None

        # Handle host extraction (URLs, host:port, [ipv6]:port, bare IPv4/IPv6/hostname)
        ip = data.get("ip")
        host_raw = data.get("host")
        if host_raw is not None and not isinstance(host_raw, str):
            raise ValueError("Nuclei 'host' must be a string")
        matched_at = data.get("matched-at")
        hostname = None
        host_val, host_port, host_is_url = (
            _split_endpoint(host_raw) if isinstance(host_raw, str) else (None, None, False)
        )
        matched_host, matched_port, _matched_is_url = (
            _split_endpoint(matched_at) if isinstance(matched_at, str) else (None, None, False)
        )
        port = host_port if host_port is not None else matched_port
        if port is None and data.get("port") is not None and not isinstance(data.get("port"), bool):
            try:
                candidate = int(str(data["port"]).split("/", 1)[0])
                if 1 <= candidate <= 65535:
                    port = candidate
            except ValueError:
                pass
        if port is None:
            for endpoint in (matched_at, host_raw):
                if isinstance(endpoint, str):
                    try:
                        parsed_endpoint = urlsplit(endpoint.strip())
                        if (parsed_endpoint.scheme in {"http", "https"} and parsed_endpoint.hostname
                                and parsed_endpoint.port is None):
                            port = 443 if parsed_endpoint.scheme == "https" else 80
                            break
                    except ValueError:
                        continue

        if not ip and host_val:
            if not host_is_url and _is_ip(host_val):
                ip = host_val
            else:
                ip = "unknown"
                hostname = host_val
        elif host_val and ip and host_val != ip:
            hostname = host_val
        if not ip:
            ip = "unknown"
        if ip == "unknown" and not hostname and matched_host:
            if _is_ip(matched_host):
                ip = matched_host
            else:
                hostname = matched_host
        host_model = Host(ip=str(ip), hostname=hostname, port=port)

        # Handle evidence
        evidence_list = []
        req = data.get("request")
        resp = data.get("response")

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
                parsed = urlsplit(matched_at.strip())
                location = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
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
            port=f"{port}/tcp" if port is not None else None,
            source_tool="nuclei"
        )


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _split_endpoint(raw: str) -> tuple[str | None, int | None, bool]:
    """Return `(host, port, is_http_url)` from a URL or network `host:port` string."""
    text = raw.strip()
    if not text:
        return None, None, False
    is_http = text.lower().startswith(("http://", "https://"))
    if "://" in text:
        try:
            parsed = urlsplit(text)
            hostname = parsed.hostname
        except ValueError:
            return None, None, is_http
        try:
            port = parsed.port
        except ValueError:
            port = None
        return hostname, port, is_http
    if text.startswith("["):
        if "]:" in text:
            host_part, _, port_part = text[1:].partition("]:")
            if port_part.isdigit() and 1 <= int(port_part) <= 65535:
                return host_part or None, int(port_part), False
            return host_part or None, None, False
        if text.endswith("]"):
            return text[1:-1] or None, None, False
    if text.count(":") == 1:
        host_part, _, port_part = text.partition(":")
        if port_part.isdigit() and 1 <= int(port_part) <= 65535:
            return host_part or None, int(port_part), False
    return text, None, False
