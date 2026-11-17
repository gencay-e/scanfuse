import json
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from scanfuse.models import Evidence, Finding, Host, Observation
from scanfuse.parsers.base import BaseParser, clean_ids, extract_urls, html_to_text


def _dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}


class SarifParser(BaseParser):
    """Parse SARIF 2.1.0 results into scanfuse findings."""

    def parse(self, file_path: str) -> list[Finding]:
        try:
            data = json.loads(Path(file_path).read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid SARIF file {file_path}: {exc}") from exc

        if not isinstance(data, dict) or data.get("version") != "2.1.0":
            raise ValueError("SARIF input must declare version 2.1.0")
        runs = data.get("runs")
        if not isinstance(runs, list):
            raise ValueError("SARIF input must contain a runs array")

        findings: list[Finding] = []

        for run in runs:
            if not isinstance(run, dict):
                continue
            source_tool = "sarif"
            tool = run.get("tool") or {}
            driver = tool.get("driver") if isinstance(tool, dict) else {}
            if isinstance(driver, dict) and driver.get("name"):
                source_tool = str(driver.get("name"))
            raw_rules = driver.get("rules") if isinstance(driver, dict) else []
            rules = raw_rules if isinstance(raw_rules, list) else []
            rule_map = {
                str(rule.get("id")): rule
                for rule in rules or []
                if isinstance(rule, dict) and rule.get("id") is not None
            }
            raw_results = run.get("results")
            results = raw_results if isinstance(raw_results, list) else []
            for result in results:
                if not isinstance(result, dict):
                    continue
                rule_id = str(result.get("ruleId") or "")
                if not rule_id and isinstance(result.get("ruleIndex"), int):
                    rule_index = result["ruleIndex"]
                    if isinstance(rules, list) and 0 <= rule_index < len(rules):
                        rule_id = str(_dict(rules[rule_index]).get("id") or "")
                rule = rule_map.get(rule_id, {})
                message = result.get("message") or {}
                if isinstance(message, dict):
                    description = html_to_text(message.get("text") or message.get("markdown") or "")
                else:
                    description = str(message)
                result_message = result.get("message")
                title_value = (
                    result_message.get("text") or result_message.get("markdown")
                    if isinstance(result_message, dict)
                    else None
                )
                # The title names the rule; the per-result message goes into the description.
                short = _dict(rule.get("shortDescription"))
                rule_title = short.get("text") or short.get("markdown") or rule.get("name")
                if rule_title:
                    title = html_to_text(rule_title)
                elif rule_id:
                    title = rule_id
                else:
                    first_line = html_to_text(title_value or "").strip().splitlines()
                    title = (first_line[0][:120] if first_line else "") or "SARIF finding"
                full_description = _dict(rule.get("fullDescription"))
                rule_text = html_to_text(full_description.get("text") or full_description.get("markdown") or "")
                if description and rule_text and rule_text != description:
                    description = f"{description}\n\n{rule_text}"
                else:
                    description = description or rule_text or title
                level = str(result.get("level") or _dict(rule.get("defaultConfiguration")).get("level") or "warning").lower()
                properties = _dict(result.get("properties"))
                rule_properties = _dict(rule.get("properties"))
                score_value = properties.get("security-severity")
                if score_value is None:
                    score_value = rule_properties.get("security-severity")
                severity = self._severity(score_value, level)
                declared_severity = properties.get("scanfuse-severity")
                if declared_severity in {"Critical", "High", "Medium", "Low", "Info"}:
                    severity = str(declared_severity)
                score = self._score(score_value)
                cvss_raw = properties.get("cvss")
                if cvss_raw is None:
                    cvss_raw = rule_properties.get("cvss")
                cvss_vector = None
                if isinstance(cvss_raw, str):
                    cvss_vector = cvss_raw
                elif isinstance(cvss_raw, dict):
                    vector = cvss_raw.get("vector")
                    cvss_vector = vector if isinstance(vector, str) else None
                elif isinstance(cvss_raw, list) and cvss_raw:
                    if isinstance(cvss_raw[0], dict):
                        vector = cvss_raw[0].get("vector")
                        cvss_vector = vector if isinstance(vector, str) else None
                    elif isinstance(cvss_raw[0], str):
                        cvss_vector = cvss_raw[0]
                locations = result.get("locations")
                if not isinstance(locations, list):
                    locations = []
                hosts: list[Host] = []
                evidence: list[Evidence] = []
                observations: list[Observation] = []
                for location in locations:
                    if not isinstance(location, dict):
                        continue
                    physical = _dict(location.get("physicalLocation"))
                    artifact = _dict(physical.get("artifactLocation"))
                    uri_raw = artifact.get("uri")
                    uri = uri_raw if isinstance(uri_raw, str) else None
                    if uri:
                        parsed = urlsplit(str(uri))
                        hostname = parsed.hostname if parsed.scheme in {"http", "https"} else None
                        if hostname and not any(h.ip == hostname for h in hosts):
                            hosts.append(Host(ip=hostname))
                    else:
                        hostname = None
                    region = _dict(physical.get("region"))
                    start_line = region.get("startLine")
                    location = f"{uri}:{start_line}" if uri and start_line is not None else (str(uri) if uri else None)
                    observations.append(Observation(host=hostname, location=location, source_tool=source_tool))
                    details = str(uri or "location")
                    if region.get("startLine") is not None:
                        details += f":{region['startLine']}"
                    if region.get("startColumn") is not None:
                        details += f":{region['startColumn']}"
                    snippet = _dict(region.get("snippet"))
                    evidence.append(Evidence(type="location", data=details, code=str(snippet.get("text") or "")))
                rule_properties = _dict(rule.get("properties"))
                reference_values = cast(list[object], rule_properties["references"]) \
                    if isinstance(rule_properties.get("references"), list) else []
                references = extract_urls(
                    rule.get("helpUri"), _dict(rule.get("help")).get("text"),
                    _dict(rule.get("help")).get("markdown"),
                    "\n".join(str(ref) for ref in reference_values),
                )
                identifiers = clean_ids(rule_id)
                identifiers.extend(clean_ids(_dict(rule.get("properties")).get("cwe")))
                findings.append(Finding(
                    title=title,
                    severity=severity,
                    cvss_score=score,
                    cvss_vector=cvss_vector,
                    description=description or title,
                    remediation=html_to_text(
                        _dict(rule.get("help")).get("text") or _dict(rule.get("help")).get("markdown")
                        or rule.get("help")
                    ) or None,
                    hosts=hosts,
                    evidence=evidence,
                    source_tool=source_tool,
                    identifiers=identifiers,
                    references=references,
                    observations=observations,
                ))
        return findings

    @staticmethod
    def _score(value: object) -> float | None:
        try:
            score = float(str(value))
        except (TypeError, ValueError):
            return None
        return score if 0 <= score <= 10 else None

    @classmethod
    def _severity(cls, score_value: object, level: str) -> str:
        score = cls._score(score_value)
        if score is not None:
            if score >= 9:
                return "Critical"
            if score >= 7:
                return "High"
            if score >= 4:
                return "Medium"
            if score > 0:
                return "Low"
            return "Info"
        return {"error": "High", "warning": "Medium", "note": "Low", "none": "Info"}.get(level, "Medium")
