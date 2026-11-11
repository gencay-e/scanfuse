import csv
import json
from pathlib import Path
from typing import Any

from defusedxml import ElementTree as ET

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import BaseParser, clean_ids, extract_urls


class NiktoParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        path = Path(file_path)
        text = path.read_text(encoding="utf-8-sig")
        stripped = text.lstrip()
        if stripped.startswith("<"):
            return self._xml(text)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return self._csv(text)
        
        if isinstance(data, list):
            findings: list[Finding] = []
            for host_entry in data:
                if not isinstance(host_entry, dict):
                    continue
                host_ip = str(host_entry.get("ip") or host_entry.get("host") or "unknown")
                port_val = host_entry.get("port")
                try:
                    port = int(port_val) if port_val is not None else None
                except (TypeError, ValueError):
                    port = None
                vulns = host_entry.get("vulnerabilities", host_entry.get("items", []))
                if isinstance(vulns, list):
                    for item in vulns:
                        if isinstance(item, dict):
                            item_copy = dict(item)
                            if "host" not in item_copy and "ip" not in item_copy:
                                item_copy["host"] = host_ip
                                name = host_entry.get("host")
                                if name and str(name) != host_ip:
                                    item_copy["targethostname"] = str(name)
                            if port is not None and "port" not in item_copy:
                                item_copy["port"] = port
                            findings.append(self._finding(item_copy))
            if findings:
                return findings
        items: list[Any]
        if isinstance(data, dict):
            raw_items = data.get("vulnerabilities", data.get("items", data.get("scanDetails", [])))
            items = raw_items if isinstance(raw_items, list) else []
        else:
            items = []

        if not isinstance(items, list):
            raise ValueError("Not a valid Nikto JSON report")
        return [self._finding(item) for item in items if isinstance(item, dict)]

    def _finding(self, item: dict[str, object]) -> Finding:
        host = str(item.get("host") or item.get("ip") or item.get("targetip") or "unknown")
        hostname = str(item.get("targethostname") or "") or None
        port_val = item.get("port") or item.get("targetport")
        try:
            port = int(str(port_val)) if port_val is not None else None
        except (TypeError, ValueError):
            port = None

        title = str(item.get("msg") or item.get("description") or item.get("id") or "Nikto finding")
        return Finding(title=title, severity=self._severity(item.get("severity")),
                       description=str(item.get("description") or item.get("msg") or title),
                       hosts=[Host(ip=host, hostname=hostname, port=port)], evidence=[Evidence(type="nikto", data=str(item))],
                       source_tool="nikto", identifiers=clean_ids(item.get("id")),
                       port=str(port) if port is not None else None,
                       references=extract_urls(item.get("url")))

    @staticmethod
    def _severity(value: object) -> str:
        return {"critical": "Critical", "high": "High", "medium": "Medium",
                "low": "Low", "info": "Info"}.get(str(value or "info").lower(), "Info")

    def _xml(self, text: str) -> list[Finding]:
        root = ET.fromstring(text)
        findings: list[Finding] = []
        for scandetails in root.findall(".//scandetails"):
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
                    "url": item.findtext("uri")
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
        header = lines[0].lower()
        if "host" not in header and "ip" not in header and "msg" not in header:
            fieldnames = ["host", "port", "id", "severity", "msg", "description"]
            reader = csv.DictReader(lines, fieldnames=fieldnames)
        else:
            reader = csv.DictReader(lines)
        return [self._finding(dict(row)) for row in reader]
