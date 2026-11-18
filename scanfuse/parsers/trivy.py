import json
import math

from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import (
    BaseParser,
    PartialImportError,
    clean_ids,
    cve_ids,
    cwe_id,
    extract_urls,
)


class TrivyParser(BaseParser):
    def parse(self, file_path: str) -> list[Finding]:
        findings = []

        with open(file_path, encoding="utf-8-sig") as f:
            try:
                data = json.load(f)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise ValueError(f"Invalid JSON in {file_path}: {e}")

        # Older Trivy versions write a bare list of results. Current versions write an object.
        if isinstance(data, list):
            if not data or not all(isinstance(item, dict) and "Target" in item for item in data):
                raise ValueError(f"Not a valid Trivy JSON file: {file_path}")
            data = {"ArtifactName": str(data[0].get("Target") or "unknown-artifact"), "Results": data}

        # Basic check to see if it looks like a Trivy report
        if not isinstance(data, dict) or ("SchemaVersion" not in data and "ArtifactName" not in data):
            raise ValueError(f"Not a valid Trivy JSON file: {file_path}")

        artifact_raw = str(data.get("ArtifactName") or "").strip()
        artifact_type = str(data.get("ArtifactType") or "").strip()
        if artifact_raw in {"", ".", "./", ".\\"}:
            host_model = Host(ip="local", hostname=artifact_type or "artifact")
        else:
            host_model = Host(ip="unknown", hostname=artifact_raw)

        severity_map = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "INFO": "Info",
            "UNKNOWN": "Info"
        }

        raw_results = data.get("Results")
        if "Results" in data and raw_results is not None and not isinstance(raw_results, list):
            raise ValueError(f"Not a valid Trivy JSON file: 'Results' must be a list in {file_path}")
        results = raw_results or []
        parse_errors: list[str] = []

        for result in results:
            if not isinstance(result, dict):
                parse_errors.append("Trivy result entry must be an object")
                continue

            target = str(result.get("Target") or "Unknown Target")

            # Parse Vulnerabilities (CVEs)
            raw_vulns = result.get("Vulnerabilities")
            if "Vulnerabilities" in result and raw_vulns is not None and not isinstance(raw_vulns, list):
                parse_errors.append(f"Trivy 'Vulnerabilities' for {target} must be a list")
                vulns: list[object] = []
            else:
                vulns = raw_vulns or []
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    parse_errors.append(f"Trivy vulnerability entry for {target} must be an object")
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
                            except (ValueError, TypeError, OverflowError):
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
            raw_misconfs = result.get("Misconfigurations")
            if "Misconfigurations" in result and raw_misconfs is not None and not isinstance(raw_misconfs, list):
                parse_errors.append(f"Trivy 'Misconfigurations' for {target} must be a list")
                misconfs: list[object] = []
            else:
                misconfs = raw_misconfs or []
            for misconf in misconfs:
                if not isinstance(misconf, dict):
                    parse_errors.append(f"Trivy misconfiguration entry for {target} must be an object")
                    continue
                misconf_status = str(misconf.get("Status") or "").strip().upper()
                if misconf_status in {"PASS", "OK", "EXCEPTION", "SKIP", "NOT_APPLICABLE"}:
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
            raw_secrets = result.get("Secrets")
            if "Secrets" in result and raw_secrets is not None and not isinstance(raw_secrets, list):
                parse_errors.append(f"Trivy 'Secrets' for {target} must be a list")
                secrets: list[object] = []
            else:
                secrets = raw_secrets or []
            for secret in secrets:
                if not isinstance(secret, dict):
                    parse_errors.append(f"Trivy secret entry for {target} must be an object")
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

        if parse_errors:
            message = "; ".join(parse_errors)
            if findings:
                raise PartialImportError(message, findings)
            raise ValueError(message)

        return findings
