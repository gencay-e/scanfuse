import xml.etree.ElementTree as ET

import defusedxml.ElementTree as defused_et

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import (
    BaseParser,
    clean_ids,
    cve_ids,
    cwe_id,
    extract_urls,
    html_to_text,
)


def _instance_text(elem: ET.Element) -> str:
    """Request, parameter, attack, evidence and extra info of one alert instance."""
    uri = elem.findtext("uri", default="").strip()
    method = elem.findtext("method", default="").strip()
    lines = []
    if uri or method:
        lines.append(f"Request: {method} {uri}".replace("Request:  ", "Request: ").strip())
    for label, tag in (("Parameter", "param"), ("Attack", "attack"), ("Evidence", "evidence")):
        value = html_to_text(elem.findtext(tag, default=""))
        if value:
            lines.append(f"{label}: {value}")
    if elem.tag == "instance":
        other = html_to_text(elem.findtext("otherinfo", default=""))
        if other:
            lines.append(f"Other info: {other}")
    return "\n".join(lines)


class ZapParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        findings = []
        try:
            context = iter(defused_et.iterparse(file_path, events=("start", "end")))

            try:
                event, root = next(context)
            except StopIteration:
                raise ValueError("Empty XML file")

            if root.tag != "OWASPZAPReport":
                raise ValueError("Not a valid ZAP XML file (missing <OWASPZAPReport> root tag)")

            risk_map = {
                "0": "Info",
                "1": "Low",
                "2": "Medium",
                "3": "High"
            }

            for event, site_elem in context:
                if event == "end" and site_elem.tag == "site":
                    host_val = site_elem.get("host", "unknown")
                    host_model = Host(ip=host_val)

                    alerts_elem = site_elem.find("alerts")
                    if alerts_elem is None:
                        site_elem.clear()
                        root.clear()
                        continue

                    for alert_elem in alerts_elem.findall("alertitem"):
                        # Newer reports have <name>; ZAP 1.x reports only have <alert>.
                        name = html_to_text(
                            alert_elem.findtext("name") or alert_elem.findtext("alert") or ""
                        ) or "Unknown Vulnerability"
                        riskcode = alert_elem.findtext("riskcode", default="0")
                        severity = risk_map.get(riskcode, "Info")

                        desc = html_to_text(alert_elem.findtext("desc", default=""))
                        solution = html_to_text(alert_elem.findtext("solution", default=""))
                        reference_text = alert_elem.findtext("reference", default="")

                        evidence_list = []
                        instances_elem = alert_elem.find("instances")
                        if instances_elem is not None:
                            for inst in instances_elem.findall("instance"):
                                text = _instance_text(inst)
                                if text:
                                    evidence_list.append(Evidence(type="http-request", data=text))
                        else:
                            # ZAP 1.x: uri, param and attack are children of the alert itself.
                            text = _instance_text(alert_elem)
                            if text:
                                evidence_list.append(Evidence(type="http-request", data=text))
                        other_info = html_to_text(alert_elem.findtext("otherinfo", default=""))
                        if other_info:
                            evidence_list.append(Evidence(type="other-info", data=other_info))

                        plugin_id = alert_elem.findtext("pluginid", default="").strip()
                        wasc = alert_elem.findtext("wascid", default="").strip()
                        identifiers = clean_ids(
                            f"zap-plugin:{plugin_id}" if plugin_id else None,
                            cwe_id(alert_elem.findtext("cweid", default="")),
                            f"WASC-{wasc}" if wasc.isdigit() and int(wasc) > 0 else None,
                            cve_ids(reference_text),
                        )

                        finding = Finding(
                            title=name,
                            severity=severity,
                            description=desc,
                            remediation=solution if solution else None,
                            hosts=[host_model],
                            evidence=evidence_list,
                            identifiers=identifiers,
                            references=extract_urls(reference_text),
                            source_tool="zap"
                        )
                        findings.append(finding)

                    site_elem.clear()
                    root.clear()

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML in {file_path}: {e}")
        except OSError as e:
            raise ValueError(f"File I/O error reading {file_path}: {e}")

        return findings
