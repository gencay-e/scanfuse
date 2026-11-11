import base64
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

import defusedxml.ElementTree as defused_et

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import (
    BaseParser,
    clean_ids,
    cve_ids,
    cwe_ids_from_text,
    extract_urls,
    html_to_text,
)


class BurpParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        findings = []
        try:
            context = iter(defused_et.iterparse(file_path, events=("start", "end")))

            try:
                event, root = next(context)
            except StopIteration:
                raise ValueError("Empty XML file")

            if root.tag != "issues":
                raise ValueError("Not a valid Burp XML file (missing <issues> root tag)")

            for event, issue_elem in context:
                if event == "end" and issue_elem.tag == "issue":
                    name = html_to_text(issue_elem.findtext("name", default="")) or "Unknown Vulnerability"
                    severity_raw = issue_elem.findtext("severity", default="Information")

                    # Map Burp severity to Finding severity model
                    severity_map = {
                        "Critical": "Critical",
                        "High": "High",
                        "Medium": "Medium",
                        "Low": "Low",
                        "Information": "Info",
                        "False positive": "Info"
                    }
                    severity = severity_map.get(severity_raw, "Info")

                    host_elem = issue_elem.find("host")
                    ip = host_elem.get("ip", "unknown") if host_elem is not None else "unknown"
                    hostname = host_elem.text if host_elem is not None else None
                    port = None
                    if hostname:
                        try:
                            u = urlsplit(hostname)
                            if u.port:
                                port = f"{u.port}/tcp"
                            elif u.scheme == "https":
                                port = "443/tcp"
                            elif u.scheme == "http":
                                port = "80/tcp"
                        except (ValueError, TypeError):
                            port = None
                    host_model = Host(ip=ip, hostname=hostname)

                    # Burp writes HTML into these fields. scanfuse keeps the text.
                    bg = html_to_text(issue_elem.findtext("issueBackground", default=""))
                    detail = html_to_text(issue_elem.findtext("issueDetail", default=""))
                    desc = "\n\n".join(part for part in (detail, bg) if part)

                    remediation = "\n\n".join(
                        part for part in (
                            html_to_text(issue_elem.findtext("remediationBackground", default="")),
                            html_to_text(issue_elem.findtext("remediationDetail", default="")),
                        ) if part
                    )

                    evidence_list = []

                    path = issue_elem.findtext("path", default="").strip()
                    if path:
                        evidence_list.append(Evidence(type="path", data=path))
                    location = html_to_text(issue_elem.findtext("location", default=""))
                    confidence = issue_elem.findtext("confidence", default="").strip()
                    if confidence or (location and location != path):
                        meta = []
                        if confidence:
                            meta.append(f"Confidence: {confidence}")
                        if location and location != path:
                            meta.append(f"Location: {location}")
                        evidence_list.append(Evidence(type="burp-details", data="\n".join(meta)))

                    req_resps = issue_elem.findall("requestresponse")
                    for rr in req_resps:
                        req_elem = rr.find("request")
                        res_elem = rr.find("response")

                        text = ""
                        if req_elem is not None and req_elem.text:
                            req_data = req_elem.text
                            if req_elem.get("base64") == "true":
                                try:
                                    req_data = base64.b64decode(req_data).decode("utf-8", errors="replace")
                                except Exception:  # noqa: S110
                                    pass
                            text += f"Request:\n{req_data}\n\n"

                        if res_elem is not None and res_elem.text:
                            res_data = res_elem.text
                            if res_elem.get("base64") == "true":
                                try:
                                    res_data = base64.b64decode(res_data).decode("utf-8", errors="replace")
                                except Exception:  # noqa: S110
                                    pass
                            text += f"Response:\n{res_data}"

                        if text.strip():
                            evidence_list.append(Evidence(type="http-request", data=text.strip()))

                    type_id = issue_elem.findtext("type", default="").strip()
                    references_html = issue_elem.findtext("references", default="")
                    classifications = issue_elem.findtext("vulnerabilityClassifications", default="")
                    identifiers = clean_ids(
                        f"burp-type:{type_id}" if type_id else None,
                        cwe_ids_from_text(classifications, references_html),
                        cve_ids(classifications + " " + references_html),
                    )

                    finding = Finding(
                        title=name,
                        severity=severity,
                        description=desc,
                        remediation=remediation if remediation else None,
                        port=port,
                        hosts=[host_model],
                        evidence=evidence_list,
                        identifiers=identifiers,
                        references=extract_urls(references_html, classifications),
                        source_tool="burp"
                    )
                    findings.append(finding)

                    issue_elem.clear()
                    root.clear()

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML in {file_path}: {e}")
        except OSError as e:
            raise ValueError(f"File I/O error reading {file_path}: {e}")

        return findings
