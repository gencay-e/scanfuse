import csv
import io
import json
from pathlib import Path
from urllib.parse import urlsplit

from defusedxml import ElementTree as ET

from scanfuse.models import Evidence, Finding, Host, Observation, host_key
from scanfuse.parsers.base import BaseParser, PartialImportError, clean_ids, extract_urls


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
            return self._xml(text)
        try:
            data = json.loads(text)
        except RecursionError as exc:
            raise ValueError("Nikto JSON nesting is too deep") from exc
        except json.JSONDecodeError:
            return self._csv(text)

        findings: list[Finding] = []
        parse_errors: list[str] = []

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
                        child = value[key]
                        if key in ("vulnerabilities", "items"):
                            if not isinstance(child, list):
                                parse_errors.append(f"Nikto '{key}' must be a list")
                                return
                        elif not isinstance(child, (list, dict)):
                            parse_errors.append(f"Nikto '{key}' must be a list or object")
                            return
                        unpack(child, inherited, depth + 1)
                        return
                if value:
                    findings.append(self._finding({**inherited, **value}))
                else:
                    parse_errors.append("Nikto entry must not be empty")
            else:
                parse_errors.append("Nikto entry must be an object")

        if isinstance(data, dict):
            if not any(key in data for key in ("vulnerabilities", "items", "scanDetails")):
                raise ValueError("Not a valid Nikto JSON report")
            unpack(data, {})
        elif isinstance(data, list):
            unpack(data, {})
        else:
            raise ValueError("Not a valid Nikto JSON report")
        if parse_errors:
            message = "; ".join(dict.fromkeys(parse_errors))
            if findings:
                raise PartialImportError(message, findings)
            raise ValueError(message)
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
        root = None
        completed_items = set()
        parse_error = None
        try:
            for event, element in ET.iterparse(io.StringIO(text), events=("start", "end")):
                if root is None:
                    root = element
                if event == "end" and element.tag == "item":
                    completed_items.add(element)
        except ET.ParseError as exc:
            parse_error = exc
        if root is None:
            raise ValueError(f"Invalid Nikto XML: {parse_error}")
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
                if item not in completed_items:
                    continue
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
                if item not in completed_items:
                    continue
                findings.append(self._finding({
                    "id": item.attrib.get("id"), "msg": item.findtext("description") or item.text,
                    "host": root.findtext(".//host") or root.attrib.get("host") or "unknown",
                }))
        if parse_error is not None:
            if findings:
                raise PartialImportError(f"Invalid Nikto XML: {parse_error}", findings)
            raise ValueError(f"Invalid Nikto XML: {parse_error}")
        return findings

    def _csv(self, text: str) -> list[Finding]:
        # Strip leading empty lines so the first record holds either the Nikto preamble or headers.
        trimmed = "\n".join(text.lstrip("\r\n").splitlines())
        if not trimmed.strip():
            return []
        raw_lines = trimmed.splitlines()
        non_empty_start = 0
        while non_empty_start < len(raw_lines) and not raw_lines[non_empty_start].strip():
            non_empty_start += 1
        trimmed = "\n".join(raw_lines[non_empty_start:])
        if not trimmed:
            return []
        rows = list(csv.reader(io.StringIO(trimmed, newline=""), escapechar="\\"))
        if not rows:
            return []
        findings: list[Finding] = []
        parse_errors: list[str] = []
        if rows[0] and rows[0][0].lower().startswith("nikto - v"):
            for line_no, row in enumerate(rows[1:], start=2):
                if not row or all(not cell.strip() for cell in row):
                    continue
                if len(row) == 1 and row[0].lower().startswith("nikto - v"):
                    continue
                if len(row) == 7:
                    if row[6]:
                        findings.append(self._finding({
                            "targethostname": row[0], "ip": row[1], "port": row[2],
                            "id": row[3], "references": row[3], "method": row[4], "uri": row[5], "msg": row[6],
                        }))
                    elif (row[0].strip() or row[1].strip()) and not any(cell.strip() for cell in row[3:6]):
                        continue
                    else:
                        parse_errors.append(f"Invalid Nikto CSV row {line_no}")
                else:
                    parse_errors.append(f"Invalid Nikto CSV row {line_no}: expected 7 columns, got {len(row)}")
        else:
            header_lower = ",".join(rows[0]).lower()
            stream = io.StringIO(trimmed, newline="")
            has_header = "host" in header_lower or "ip" in header_lower or "msg" in header_lower
            if not has_header:
                fieldnames = ["host", "port", "id", "severity", "msg", "description"]
                reader = csv.DictReader(stream, fieldnames=fieldnames)
            else:
                reader = csv.DictReader(stream)
                reader.fieldnames = [name.strip().lower() if name else name for name in (reader.fieldnames or [])]
            for line_no, record in enumerate(reader, start=2 if has_header else 1):
                if not any(val for val in record.values()):
                    continue
                if None in record or (has_header and any(v is None for k, v in record.items() if k is not None)):
                    parse_errors.append(f"Invalid Nikto CSV row {line_no}")
                    continue
                findings.append(self._finding(dict(record)))
        if parse_errors:
            message = "; ".join(dict.fromkeys(parse_errors))
            if findings:
                raise PartialImportError(message, findings)
            raise ValueError(message)
        return findings
