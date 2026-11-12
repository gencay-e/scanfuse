import ipaddress
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

import defusedxml.ElementTree as defused_et

from scanfuse.models import Evidence, Finding, Host, Observation, host_key
from scanfuse.parsers.base import (
    BaseParser,
    clean_ids,
    cve_ids,
    cwe_id,
    extract_urls,
    html_to_text,
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except (ValueError, AttributeError):
        return False


def _instance_location(elem: ET.Element) -> str | None:
    """URL path of one alert instance, with the parameter if there is one."""
    uri = elem.findtext("uri", default="").strip()
    if not uri:
        return None
    parts = urlsplit(uri)
    location = parts.path or "/"
    param = html_to_text(elem.findtext("param", default=""))
    return f"{location} [{param} parameter]" if param else location


def _instance_method(elem: ET.Element) -> str | None:
    """HTTP method of one alert instance, upper case, or None."""
    return elem.findtext("method", default="").strip().upper() or None


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
                    port_raw = site_elem.get("port")
                    port = f"{port_raw}/tcp" if port_raw and port_raw != "0" else None
                    if _is_ip(host_val):
                        host_model = Host(ip=host_val)
                    elif host_val and host_val != "unknown":
                        host_model = Host(ip="unknown", hostname=host_val)
                    else:
                        host_model = Host(ip="unknown")

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
                        observations: list[Observation] = []
                        site = host_key(host_model)
                        instances_elem = alert_elem.find("instances")
                        if instances_elem is not None:
                            instances = instances_elem.findall("instance")
                        else:
                            # ZAP 1.x: uri, param and attack are children of the alert itself.
                            instances = [alert_elem]
                        for inst in instances:
                            observations.append(Observation(
                                host=site, method=_instance_method(inst),
                                location=_instance_location(inst), source_tool="zap",
                            ))
                            text = _instance_text(inst)
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
                            port=port,
                            observations=observations,
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
