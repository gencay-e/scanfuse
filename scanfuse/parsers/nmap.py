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
        accuracy_raw = match.get("accuracy")
        try:
            accuracy = int(accuracy_raw) if accuracy_raw is not None else -1
        except ValueError:
            accuracy = -1
        if name and (best_name is None or accuracy > best_accuracy):
            best_name, best_accuracy = name, accuracy
    if best_name is None:
        return None
    if best_accuracy >= 0:
        return f"{best_name} ({best_accuracy}%)"
    return best_name


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
                        # Prioritize user-provided hostnames over PTR/reverse-DNS
                        user_name = None
                        first_name = None
                        for hn in hostnames.findall("hostname"):
                            n = hn.get("name")
                            if n:
                                if hn.get("type") == "user" and not user_name:
                                    user_name = n
                                if not first_name:
                                    first_name = n
                        hostname = user_name or first_name

                    host_model = Host(ip=ip, hostname=hostname, os=_best_os_guess(host_elem))

                    ports_elem = host_elem.find("ports")
                    if ports_elem is not None:
                        for port_elem in ports_elem.findall("port"):
                            state_elem = port_elem.find("state")
                            state = state_elem.get("state") if state_elem is not None else ""
                            if state not in ("open", "open|filtered"):
                                continue

                            protocol = port_elem.get("protocol", "tcp")
                            portid = port_elem.get("portid", "")

                            service_elem = port_elem.find("service")
                            service_name = ""
                            product = ""
                            version = ""
                            if service_elem is not None:
                                service_name = (service_elem.get("name") or "").strip()
                                product = (service_elem.get("product") or "").strip()
                                version = (service_elem.get("version") or "").strip()

                            cpes = (
                                [c.text.strip() for c in service_elem.findall("cpe") if c.text and c.text.strip()]
                                if service_elem is not None else []
                            )

                            prod_ver = f"{product} {version}".strip()
                            if service_name and prod_ver:
                                service_desc = f"{service_name} ({prod_ver})"
                            elif service_name:
                                service_desc = service_name
                            elif prod_ver:
                                service_desc = prod_ver
                            else:
                                service_desc = "unknown"

                            title_prefix = "Open Port" if state == "open" else "Open/Filtered Port"
                            title = f"{title_prefix}: {portid}/{protocol} ({service_desc})"

                            evidence_text = f"Port: {portid}/{protocol}\nState: {state}\nService: {service_name or 'unknown'}"
                            if product:
                                evidence_text += f"\nProduct: {product}"
                            if version:
                                evidence_text += f"\nVersion: {version}"

                            for script in port_elem.findall("script"):
                                script_id = script.get("id", "")
                                script_output = script.get("output", "")
                                if not script_output:
                                    # Fallback to script.text or structured child elements
                                    script_output = (script.text or "").strip()
                                    if not script_output:
                                        elems = [
                                            (e.get("key") + ": " if e.get("key") else "") + (e.text or "")
                                            for e in script.iter()
                                            if e is not script and (e.text or "").strip()
                                        ]
                                        script_output = "; ".join(elems).strip()
                                evidence_text += f"\nScript {script_id}: {script_output}".rstrip()

                            evidence = Evidence(
                                type="port-scan",
                                data=evidence_text.strip()
                            )

                            finding = Finding(
                                title=title,
                                severity="Info",
                                description=f"A {state} {protocol} port was discovered on port {portid} running {service_desc}.",
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
