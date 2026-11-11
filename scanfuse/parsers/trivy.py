import json
import math

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import BaseParser, clean_ids, cve_ids, cwe_id, extract_urls


class TrivyParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        findings = []

        with open(file_path, encoding="utf-8-sig") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in {file_path}: {e}")

        # Older Trivy versions write a bare list of results. Current versions write an object.
        if isinstance(data, list):
            if not data or not all(isinstance(item, dict) and "Target" in item for item in data):
                raise ValueError(f"Not a valid Trivy JSON file: {file_path}")
            data = {"ArtifactName": str(data[0].get("Target") or "unknown-artifact"), "Results": data}

        # Basic check to see if it looks like a Trivy report
        if not isinstance(data, dict) or ("SchemaVersion" not in data and "ArtifactName" not in data):
            raise ValueError(f"Not a valid Trivy JSON file: {file_path}")

        artifact_name = data.get("ArtifactName", "unknown-artifact")
        host_model = Host(ip="unknown", hostname=artifact_name)

        severity_map = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Info",
            "UNKNOWN": "Info"
        }

        results = data.get("Results") or []
        if not isinstance(results, list):
            results = []

        for result in results:
            if not isinstance(result, dict):
                continue

            target = str(result.get("Target") or "Unknown Target")

            # Parse Vulnerabilities (CVEs)
            vulns = result.get("Vulnerabilities") or []
            if not isinstance(vulns, list):
                vulns = []
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = vuln.get("VulnerabilityID", "Unknown ID")
                pkg_name = vuln.get("PkgName", "")
                title_raw = vuln.get("Title")
                title = str(title_raw).strip() if title_raw else f"{vuln_id} in {pkg_name}"

                desc_raw = vuln.get("Description")
                desc = str(desc_raw).strip() if desc_raw else ""
                sev_raw = str(vuln.get("Severity") or "UNKNOWN").upper()
                severity = severity_map.get(sev_raw, "Info")

                installed_ver = vuln.get("InstalledVersion", "")
                fixed_ver = vuln.get("FixedVersion", "")

                remediation = f"Update {pkg_name} from {installed_ver} to {fixed_ver}." if fixed_ver else None

                # Extract CVSS if present
                cvss_score = None
                cvss_vector = None
                cvss_data = vuln.get("CVSS", {})
                if isinstance(cvss_data, dict) and cvss_data:
                    # Prefer NVD V3, fallback to whatever is there
                    for provider, scores in cvss_data.items():
                        if isinstance(scores, dict) and "V3Score" in scores:
                            val = scores.get("V3Score")
                            try:
                                cvss_val = float(val) if val is not None else None
                                if cvss_val is not None and (not math.isfinite(cvss_val) or cvss_val < 0.0 or cvss_val > 10.0):
                                    cvss_val = None
                            except (ValueError, TypeError):
                                cvss_val = None
                            vector = scores.get("V3Vector")
                            vector = vector if isinstance(vector, str) else None
                            if cvss_val is None:
                                if cvss_score is None and cvss_vector is None:
                                    cvss_vector = vector
                                continue
                            cvss_score = cvss_val
                            cvss_vector = vector
                            if provider == "nvd":
                                break

                evidence_list = [Evidence(type="target", data=target)]
                if pkg_name:
                    evidence_list.append(Evidence(type="package", data=f"Package: {pkg_name}\nInstalled: {installed_ver}"))

                cwe_ids = vuln.get("CweIDs")
                vuln_identifiers = clean_ids(
                    cve_ids(vuln_id) or (vuln_id if vuln_id != "Unknown ID" else None),
                    [cwe_id(c) for c in cwe_ids] if isinstance(cwe_ids, list) else None,
                )

                finding = Finding(
                    title=title,
                    severity=severity,
                    description=desc,
                    remediation=remediation,
                    identifiers=vuln_identifiers,
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    references=extract_urls(vuln.get("PrimaryURL"), vuln.get("References")),
                    hosts=[host_model],
                    evidence=evidence_list,
                    source_tool="trivy"
                )
                findings.append(finding)

            # Parse Misconfigurations (IaC)
            misconfs = result.get("Misconfigurations") or []
            if not isinstance(misconfs, list):
                misconfs = []
            for misconf in misconfs:
                if not isinstance(misconf, dict):
                    continue
                misconf_id = misconf.get("ID") or "Unknown ID"
                title_raw = misconf.get("Title")
                title = str(title_raw).strip() if title_raw else str(misconf_id)

                desc_raw = misconf.get("Description")
                desc = str(desc_raw).strip() if desc_raw else ""

                sev_raw = str(misconf.get("Severity") or "UNKNOWN").upper()
                severity = severity_map.get(sev_raw, "Info")

                rem_raw = misconf.get("Resolution")
                remediation = str(rem_raw).strip() if rem_raw else ""

                evidence_list = [Evidence(type="target", data=target)]
                cause = misconf.get("CauseMetadata", {})
                if isinstance(cause, dict) and cause:
                    cause_text = f"Provider: {cause.get('Provider', '')}\nService: {cause.get('Service', '')}"
                    code_data = cause.get("Code")
                    if isinstance(code_data, dict) and "Lines" in code_data:
                        lines = code_data.get("Lines") or []
                        if isinstance(lines, list):
                            code_str = "\n".join([str(line.get("Content", "")) for line in lines if isinstance(line, dict)])
                            if code_str:
                                cause_text += f"\nCode snippet:\n{code_str}"
                    elif code_data:
                        cause_text += f"\nCode snippet:\n{code_data}"
                    evidence_list.append(Evidence(type="cause", data=cause_text.strip()))
                elif cause:
                    evidence_list.append(Evidence(type="cause", data=str(cause).strip()))

                finding = Finding(
                    title=title,
                    severity=severity,
                    description=desc,
                    remediation=remediation if remediation else None,
                    identifiers=clean_ids(f"trivy-id:{misconf_id}" if misconf.get("ID") else None),
                    references=extract_urls(misconf.get("PrimaryURL"), misconf.get("References")),
                    hosts=[host_model],
                    evidence=evidence_list,
                    source_tool="trivy"
                )
                findings.append(finding)

            # Parse Secrets
            secrets = result.get("Secrets") or []
            if not isinstance(secrets, list):
                secrets = []
            for secret in secrets:
                if not isinstance(secret, dict):
                    continue
                sec_id = secret.get("RuleID") or "Unknown Secret"
                title_raw = secret.get("Title")
                title = str(title_raw).strip() if title_raw else str(sec_id)
                desc = f"Secret detected: {sec_id}"
                sev_raw = str(secret.get("Severity") or "CRITICAL").upper()
                severity = severity_map.get(sev_raw, "Critical")

                evidence_list = [Evidence(type="target", data=target)]
                if secret.get("Match"):
                    evidence_list.append(Evidence(type="match", data=f"Match: {secret.get('Match')}"))

                finding = Finding(
                    title=title,
                    severity=severity,
                    description=desc,
                    identifiers=clean_ids(f"trivy-rule:{sec_id}" if secret.get("RuleID") else None),
                    hosts=[host_model],
                    evidence=evidence_list,
                    source_tool="trivy"
                )
                findings.append(finding)

        return findings
