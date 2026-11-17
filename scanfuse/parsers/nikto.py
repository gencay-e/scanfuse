import csv
import json
from pathlib import Path
from urllib.parse import urlsplit

from defusedxml import ElementTree as ET

from scanfuse.models import Evidence, Finding, Host, Observation, host_key
from scanfuse.parsers.base import BaseParser, clean_ids, extract_urls


class NiktoParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        path = Path(file_path)
        raw = path.read_bytes()
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            try:
                text = raw.decode("utf-16")
            except UnicodeDecodeError as exc:
                raise ValueError(f"Invalid Nikto text in {file_path}: {exc}") from exc
        else:
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                try:
                    text = raw.decode("utf-16")
                except UnicodeDecodeError:
                    text = raw.decode("latin-1", errors="replace")
        stripped = text.lstrip()
        if stripped.startswith("<"):
            try:
                return self._xml(text)
            except ET.ParseError as exc:
                raise ValueError(f"Invalid Nikto XML in {file_path}: {exc}") from exc
        try:
            data = json.loads(text)
        except RecursionError as exc:
            raise ValueError("Nikto JSON nesting is too deep") from exc
        except json.JSONDecodeError:
            return self._csv(text)

        findings: list[Finding] = []

        def unpack(value: object, target: dict[str, object], depth: int = 0) -> None:
            if depth > 128:
                raise ValueError("Nikto JSON nesting is too deep")
            if isinstance(value, list):
                for entry in value:
                    unpack(entry, target, depth + 1)
            elif isinstance(value, dict):
                inherited = {**target, **{key: value[key] for key in
                             ("host", "ip", "port", "targethostname", "targetip", "targetport")
                             if key in value}}
                for key in ("vulnerabilities", "items", "scanDetails"):
                    if key in value:
                        unpack(value[key], inherited, depth + 1)
                        return
                if value:
                    findings.append(self._finding({**inherited, **value}))

        if isinstance(data, dict):
            for key in ("vulnerabilities", "items", "scanDetails"):
                if key in data:
                    unpack(data, {})
                    break
        elif isinstance(data, list):
            unpack(data, {})
        else:
            raise ValueError("Not a valid Nikto JSON report")
        return findings

    def _finding(self, item: dict[str, object]) -> Finding:
        host = str(item.get("ip") or item.get("targetip") or item.get("host") or "unknown")
        hostname = str(item.get("targethostname") or (item.get("host") if item.get("ip") else "") or "") or None
        port_val = item.get("port") or item.get("targetport")
        try:
            port = int(str(port_val)) if port_val is not None else None
        except (TypeError, ValueError):
            port = None

        title = str(item.get("msg") or item.get("description") or item.get("id") or "Nikto finding")
        url = str(item.get("url") or item.get("uri") or item.get("namelink") or "")
        location = url
        if url.startswith(("http://", "https://")):
            try:
                parsed = urlsplit(url)
                location = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
            except ValueError:
                location = url
        method = str(item.get("method") or "").strip().upper() or None
        observations = [Observation(host=host_key(Host(ip=host, hostname=hostname)), method=method, location=location or None, source_tool="nikto")]
        return Finding(title=title, severity=self._severity(item.get("severity")),
                       description=str(item.get("description") or item.get("msg") or title),
                       hosts=[Host(ip=host, hostname=hostname, port=port)], evidence=[Evidence(type="nikto", data=str(item))],
                       source_tool="nikto", identifiers=clean_ids(item.get("id")),
                       port=f"{port}/tcp" if port is not None else None,
                       references=extract_urls(item.get("url"), item.get("uri"), item.get("namelink"),
                                             item.get("references")), observations=observations)

    @staticmethod
    def _severity(value: object) -> str:
        return {"critical": "Critical", "high": "High", "medium": "Medium",
                "low": "Low", "info": "Info"}.get(str(value or "info").lower(), "Info")

    def _xml(self, text: str) -> list[Finding]:
        root = ET.fromstring(text)
        root_name = root.tag.rsplit("}", 1)[-1]
        if root_name not in {"niktoscan", "scandetails"}:
            raise ValueError(f"Not a valid Nikto XML report: unexpected root {root_name!r}")
        findings: list[Finding] = []
        scan_details = root.findall(".//scandetails")
        if root.tag.rsplit("}", 1)[-1] == "scandetails":
            scan_details.insert(0, root)
        for scandetails in scan_details:
            target_ip = scandetails.attrib.get("targetip") or root.findtext(".//host") or "unknown"
            target_host = scandetails.attrib.get("targethostname") or None
            target_port = scandetails.attrib.get("targetport")
            try:
                port = int(target_port) if target_port is not None else None
            except (TypeError, ValueError):
                port = None
            for item in scandetails.findall(".//item"):
                msg = item.findtext("description") or item.text or "Nikto finding"
                item_id = item.attrib.get("id")
                findings.append(self._finding({
                    "id": item_id,
                    "msg": msg,
                    "host": target_ip,
                    "targethostname": target_host,
                    "port": port,
                    "url": item.findtext("uri"),
                    "references": item.findtext("references"),
                    "method": item.attrib.get("method"), "namelink": item.findtext("namelink"),
                }))
        if not findings:
            for item in root.findall(".//item"):
                findings.append(self._finding({
                    "id": item.attrib.get("id"), "msg": item.findtext("description") or item.text,
                    "host": root.findtext(".//host") or root.attrib.get("host") or "unknown",
                }))
        return findings

    def _csv(self, text: str) -> list[Finding]:
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            return []
        if lines[0].lstrip('"').lower().startswith("nikto - v"):
            rows = csv.reader(lines[1:], escapechar="\\")
            return [self._finding({"targethostname": row[0], "ip": row[1], "port": row[2],
                                   "id": row[3], "references": row[3], "method": row[4], "uri": row[5], "msg": row[6]})
                    for row in rows if len(row) == 7 and row[6]]
        header = lines[0].lower()
        if "host" not in header and "ip" not in header and "msg" not in header:
            fieldnames = ["host", "port", "id", "severity", "msg", "description"]
            reader = csv.DictReader(lines, fieldnames=fieldnames)
        else:
            reader = csv.DictReader(lines)
            reader.fieldnames = [name.strip().lower() if name else name for name in (reader.fieldnames or [])]
        return [self._finding(dict(row)) for row in reader]
