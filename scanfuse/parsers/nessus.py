import xml.etree.ElementTree as ET

import defusedxml.ElementTree as defused_et

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import BaseParser, clean_ids, cve_ids, cwe_id, extract_urls


class NessusParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        findings = []
        try:
            context = iter(defused_et.iterparse(file_path, events=("start", "end")))

            try:
                event, root = next(context)
            except StopIteration:
                raise ValueError("Empty XML file")

            if root.tag != "NessusClientData_v2":
                raise ValueError("Not a valid Nessus file (missing <NessusClientData_v2> root tag)")

            severity_map = {
                "0": "Info",
                "1": "Low",
                "2": "Medium",
                "3": "High",
                "4": "Critical"
            }

            for event, report_host in context:
                if event == "end" and report_host.tag == "ReportHost":
                    # Extract Host Properties
                    host_ip = "unknown"
                    host_fqdn = None
                    host_os = None

                    host_props = report_host.find("HostProperties")
                    if host_props is not None:
                        for tag in host_props.findall("tag"):
                            name = tag.get("name")
                            if name == "host-ip":
                                host_ip = tag.text or "unknown"
                            elif name == "host-fqdn":
                                host_fqdn = tag.text
                            elif name == "operating-system":
                                host_os = tag.text

                    # Fallback if host-ip is missing but ReportHost name is an IP
                    if host_ip == "unknown":
                        host_ip = report_host.get("name", "unknown")

                    host_model = Host(ip=host_ip, hostname=host_fqdn, os=host_os)

                    # Extract Report Items (Findings)
                    for item in report_host.findall("ReportItem"):
                        sev_num = item.get("severity", "0")
                        severity = severity_map.get(sev_num, "Info")

                        name = item.get("pluginName", "Unknown Plugin")

                        description = item.findtext("description", default="").strip()
                        synopsis = item.findtext("synopsis", default="").strip()
                        if synopsis and synopsis not in description:
                            description = f"{synopsis}\n\n{description}".strip()
                        solution = item.findtext("solution", default="").strip()
                        if solution.lower() in ("n/a", "none", "na"):
                            solution = ""
                        plugin_output = item.findtext("plugin_output", default="").strip()
                        cvss = item.findtext("cvss_base_score", default="").strip()
                        cvss_vector = item.findtext("cvss_vector", default="").strip()
                        if not cvss:  # newer plugins only carry CVSS v3
                            cvss = item.findtext("cvss3_base_score", default="").strip()
                            cvss_vector = item.findtext("cvss3_vector", default="").strip()

                        evidence_list = []

                        port = item.get("port", "0")
                        protocol = item.get("protocol", "")
                        if port != "0":
                            port_text = f"Port: {port}/{protocol}"
                            svc_name = item.get("svc_name")
                            if svc_name:
                                port_text += f"\nService: {svc_name}"
                            evidence_list.append(Evidence(type="port-info", data=port_text))

                        if plugin_output:
                            evidence_list.append(Evidence(type="plugin-output", data=plugin_output))

                        try:
                            cvss_val = float(cvss) if cvss else None
                        except ValueError:
                            cvss_val = None

                        plugin_id = item.get("pluginID")
                        identifiers = clean_ids(
                            f"nessus-plugin:{plugin_id}" if plugin_id else None,
                            cve_ids([c.text for c in item.findall("cve")]),
                            cwe_id(item.findtext("cwe")),
                        )

                        finding = Finding(
                            title=name,
                            severity=severity,
                            description=description,
                            remediation=solution if solution else None,
                            cvss_score=cvss_val,
                            cvss_vector=cvss_vector if cvss_vector else None,
                            hosts=[host_model],
                            evidence=evidence_list,
                            source_tool="nessus",
                            identifiers=identifiers,
                            references=extract_urls(item.findtext("see_also", default="")),
                            port=f"{port}/{protocol}" if port != "0" else None,
                        )
                        findings.append(finding)

                    report_host.clear()
                    root.clear()

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML in {file_path}: {e}")
        except OSError as e:
            raise ValueError(f"File I/O error reading {file_path}: {e}")

        return findings
