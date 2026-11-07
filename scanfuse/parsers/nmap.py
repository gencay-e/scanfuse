import xml.etree.ElementTree as ET

import defusedxml.ElementTree as defused_et

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import BaseParser, clean_ids


def _best_os_guess(host_elem: ET.Element) -> str | None:
    """The operating system guess with the highest accuracy, e.g. 'Linux 5.0 - 5.7 (97%)'."""
    os_elem = host_elem.find("os")
    if os_elem is None:
        return None
    best_name, best_accuracy = None, -1
    for match in os_elem.findall("osmatch"):
        name = match.get("name")
        try:
            accuracy = int(match.get("accuracy", "0"))
        except ValueError:
            accuracy = 0
        if name and accuracy > best_accuracy:
            best_name, best_accuracy = name, accuracy
    if best_name is None:
        return None
    return f"{best_name} ({best_accuracy}%)"


class NmapParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        findings = []
        try:
            context = iter(defused_et.iterparse(file_path, events=("start", "end")))

            try:
                event, root = next(context)
            except StopIteration:
                raise ValueError("Empty XML file")

            if root.tag != "nmaprun":
                raise ValueError("Not a valid Nmap XML file (missing <nmaprun> root tag)")

            for event, host_elem in context:
                if event == "end" and host_elem.tag == "host":
                    status = host_elem.find("status")
                    if status is not None and status.get("state") != "up":
                        host_elem.clear()
                        root.clear()
                        continue

                    ip = ""
                    for address in host_elem.findall("address"):
                        if address.get("addrtype") in ("ipv4", "ipv6"):
                            ip = address.get("addr")
                            break

                    if not ip:
                        host_elem.clear()
                        root.clear()
                        continue

                    hostname = None
                    hostnames = host_elem.find("hostnames")
                    if hostnames is not None:
                        for hn in hostnames.findall("hostname"):
                            if hn.get("name"):
                                hostname = hn.get("name")
                                break

                    host_model = Host(ip=ip, hostname=hostname, os=_best_os_guess(host_elem))

                    ports_elem = host_elem.find("ports")
                    if ports_elem is not None:
                        for port_elem in ports_elem.findall("port"):
                            state_elem = port_elem.find("state")
                            if state_elem is None or state_elem.get("state") != "open":
                                continue

                            protocol = port_elem.get("protocol", "tcp")
                            portid = port_elem.get("portid", "")

                            service_elem = port_elem.find("service")
                            service_name = "unknown"
                            product = ""
                            version = ""
                            if service_elem is not None:
                                service_name = service_elem.get("name", service_name)
                                product = service_elem.get("product", "")
                                version = service_elem.get("version", "")

                            cpes = (
                                [c.text.strip() for c in service_elem.findall("cpe") if c.text and c.text.strip()]
                                if service_elem is not None else []
                            )

                            service_desc = service_name
                            if product:
                                service_desc += f" ({f'{product} {version}'.strip()})"

                            title = f"Open Port: {portid}/{protocol} ({service_desc})"

                            evidence_text = f"Port: {portid}/{protocol}\nState: open\nService: {service_name}"
                            if product:
                                evidence_text += f"\nProduct: {product}"
                            if version:
                                evidence_text += f"\nVersion: {version}"

                            for script in port_elem.findall("script"):
                                script_id = script.get("id", "")
                                script_output = script.get("output", "")
                                evidence_text += f"\nScript {script_id}: {script_output}"

                            evidence = Evidence(
                                type="port-scan",
                                data=evidence_text.strip()
                            )

                            finding = Finding(
                                title=title,
                                severity="Info",
                                description=f"An open {protocol} port was discovered on port {portid} running {service_desc}.",
                                hosts=[host_model],
                                evidence=[evidence],
                                source_tool="nmap",
                                identifiers=clean_ids(cpes),
                                port=f"{portid}/{protocol}" if portid else None,
                            )
                            findings.append(finding)

                    host_elem.clear()
                    root.clear()

        except ET.ParseError as e:
            raise ValueError(f"Invalid XML in {file_path}: {e}")
        except OSError as e:
            raise ValueError(f"File I/O error reading {file_path}: {e}")

        return findings
