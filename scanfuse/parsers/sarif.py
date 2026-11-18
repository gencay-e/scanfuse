import json
import re
from pathlib import Path
from typing import cast
from urllib.parse import urljoin, urlsplit

from pydantic import ValidationError

from scanfuse.models import Evidence, Finding, Host, Observation
from scanfuse.parsers.base import (
    BaseParser,
    PartialImportError,
    as_dict,
    clean_ids,
    extract_urls,
)


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
        parse_errors: list[str] = []

        for run in runs:
            if not isinstance(run, dict):
                parse_errors.append("SARIF run entry must be an object")
                continue
            invocations = run.get("invocations")
            if "invocations" in run and invocations is not None and not isinstance(invocations, list):
                parse_errors.append("SARIF run 'invocations' must be a list")
            elif isinstance(invocations, list):
                for inv in invocations:
                    if not isinstance(inv, dict):
                        parse_errors.append("SARIF invocation entry must be an object")
                    elif inv.get("executionSuccessful") is False:
                        parse_errors.append("SARIF invocation did not complete (executionSuccessful=false)")
            source_tool = "sarif"
            tool = run.get("tool") or {}
            driver = tool.get("driver") if isinstance(tool, dict) else {}
            raw_rules = driver.get("rules") if isinstance(driver, dict) else []
            if isinstance(driver, dict) and driver.get("name"):
                source_tool = str(driver.get("name"))
            if isinstance(driver, dict) and "rules" in driver and raw_rules is not None and not isinstance(raw_rules, list):
                parse_errors.append("SARIF driver 'rules' must be a list")
            rules = raw_rules if isinstance(raw_rules, list) else []
            rule_map = {
                str(rule.get("id")): rule
                for rule in rules or []
                if isinstance(rule, dict) and rule.get("id") is not None
            }
            raw_artifacts = run.get("artifacts")
            if "artifacts" in run and raw_artifacts is not None and not isinstance(raw_artifacts, list):
                parse_errors.append("SARIF run 'artifacts' must be a list")
            artifacts = raw_artifacts if isinstance(raw_artifacts, list) else []
            raw_results = run.get("results")
            if "results" in run and raw_results is not None and not isinstance(raw_results, list):
                parse_errors.append("SARIF run 'results' must be a list")
                continue
            results = raw_results if isinstance(raw_results, list) else []
            for result in results:
                if not isinstance(result, dict):
                    parse_errors.append("SARIF result entry must be an object")
                    continue
                properties = as_dict(result.get("properties"))
                if source_tool == "scanfuse" and "scanfuse-finding-version" in properties:
                    if properties["scanfuse-finding-version"] != 1:
                        parse_errors.append("Unsupported scanfuse SARIF finding version")
                        continue
                    try:
                        findings.append(Finding.model_validate(properties))
                    except ValidationError as exc:
                        parse_errors.append(f"Invalid scanfuse SARIF finding: {exc}")
                    continue
                kind = str(result.get("kind") or "").strip().lower()
                if kind in {"pass", "notapplicable"}:
                    continue
                rule_id = str(result.get("ruleId") or "")
                if not rule_id and isinstance(result.get("ruleIndex"), int):
                    rule_index = result["ruleIndex"]
                    if isinstance(rules, list) and 0 <= rule_index < len(rules):
                        rule_id = str(as_dict(rules[rule_index]).get("id") or "")
                rule = rule_map.get(rule_id, {})
                try:
                    description = self._message(result.get("message"), rule, as_dict(driver))
                except ValueError as exc:
                    parse_errors.append(str(exc))
                    description = self._text(result.get("message"))
                # The title names the rule; the per-result message goes into the description.
                short = as_dict(rule.get("shortDescription"))
                rule_title = self._text(short) or self._text(rule.get("name"))
                if rule_title:
                    title = rule_title.strip()
                elif rule_id:
                    title = rule_id
                else:
                    first_line = description.strip().splitlines()
                    title = (first_line[0][:120] if first_line else "") or "SARIF finding"
                full_description = as_dict(rule.get("fullDescription"))
                rule_text = self._text(full_description)
                if description and rule_text and rule_text != description:
                    description = f"{description}\n\n{rule_text}"
                else:
                    description = description or rule_text or title
                level = str(result.get("level") or as_dict(rule.get("defaultConfiguration")).get("level") or "warning").lower()
                properties = as_dict(result.get("properties"))
                rule_properties = as_dict(rule.get("properties"))
                score_value = properties.get("security-severity")
                if score_value is None:
                    score_value = rule_properties.get("security-severity")
                severity = self._severity(score_value, level)
                declared_severity = properties.get("scanfuse-severity")
                if isinstance(declared_severity, str) and declared_severity in {"Critical", "High", "Medium", "Low", "Info"}:
                    severity = declared_severity
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
                    physical = as_dict(location.get("physicalLocation"))
                    artifact = as_dict(physical.get("artifactLocation"))
                    uri_raw = artifact.get("uri")
                    if not isinstance(uri_raw, str) or not uri_raw:
                        art_index = artifact.get("index")
                        if isinstance(art_index, int) and not isinstance(art_index, bool):
                            if 0 <= art_index < len(artifacts) and isinstance(artifacts[art_index], dict):
                                art_loc = as_dict(artifacts[art_index].get("location"))
                                uri_raw = art_loc.get("uri")
                                artifact = {**art_loc, **artifact, "uri": uri_raw}
                            else:
                                parse_errors.append(f"SARIF artifactLocation index {art_index} out of range")
                    try:
                        uri = self._artifact_uri(artifact, as_dict(run.get("originalUriBaseIds")))
                        parsed = urlsplit(uri or "")
                        hostname = parsed.hostname if parsed.scheme in {"http", "https"} else None
                    except ValueError as exc:
                        parse_errors.append(str(exc))
                        uri = uri_raw if isinstance(uri_raw, str) else None
                        hostname = None
                    if hostname and not any(h.ip == hostname for h in hosts):
                        hosts.append(Host(ip=hostname))
                    region = as_dict(physical.get("region"))
                    start_line = region.get("startLine")
                    location = f"{uri}:{start_line}" if uri and start_line is not None else (str(uri) if uri else None)
                    observations.append(Observation(host=hostname, location=location, source_tool=source_tool))
                    details = str(uri or "location")
                    if region.get("startLine") is not None:
                        details += f":{region['startLine']}"
                    if region.get("startColumn") is not None:
                        details += f":{region['startColumn']}"
                    snippet = as_dict(region.get("snippet"))
                    evidence.append(Evidence(type="location", data=details, code=str(snippet.get("text") or "")))
                rule_properties = as_dict(rule.get("properties"))
                reference_values = cast(list[object], rule_properties["references"]) \
                    if isinstance(rule_properties.get("references"), list) else []
                references = extract_urls(
                    rule.get("helpUri"), as_dict(rule.get("help")).get("text"),
                    as_dict(rule.get("help")).get("markdown"),
                    "\n".join(str(ref) for ref in reference_values),
                )
                identifiers = clean_ids(rule_id)
                identifiers.extend(clean_ids(as_dict(rule.get("properties")).get("cwe")))
                findings.append(Finding(
                    title=title,
                    severity=severity,
                    cvss_score=score,
                    cvss_vector=cvss_vector,
                    description=description or title,
                    remediation=self._text(rule.get("help")) or None,
                    hosts=hosts,
                    evidence=evidence,
                    source_tool=source_tool,
                    identifiers=identifiers,
                    references=references,
                    observations=observations,
                ))
        if parse_errors:
            raise PartialImportError("; ".join(dict.fromkeys(parse_errors)), findings)
        return findings

    @staticmethod
    def _text(value: object) -> str:
        if isinstance(value, dict):
            value = value.get("text") or value.get("markdown")
        return value if isinstance(value, str) else ""

    @classmethod
    def _message(cls, value: object, rule: dict, driver: dict) -> str:
        message = as_dict(value)
        text = cls._text(value)
        if not text and isinstance(message.get("id"), str):
            message_id = message["id"]
            text = cls._text(as_dict(rule.get("messageStrings")).get(message_id))
            if not text:
                text = cls._text(as_dict(driver.get("globalMessageStrings")).get(message_id))
            if not text:
                raise ValueError(f"Unresolved SARIF message id: {message_id!r}")
        arguments = message.get("arguments")

        def substitute(match: re.Match[str]) -> str:
            token = match.group(0)
            if token in {"{{", "}}"}:
                return token[0]
            if not isinstance(arguments, list):
                raise ValueError("SARIF message placeholders require an arguments array")
            index = int(match.group(1))
            if index >= len(arguments) or not isinstance(arguments[index], str):
                raise ValueError(f"Invalid SARIF message argument: {index}")
            return arguments[index]

        return re.sub(r"\{\{|\}\}|\{([0-9]+)\}", substitute, text)

    @staticmethod
    def _artifact_uri(artifact: dict, bases: dict) -> str | None:
        uri = artifact.get("uri")
        if not isinstance(uri, str) or not uri:
            return None
        seen: set[str] = set()
        relative_uris: list[str] = []
        while not urlsplit(uri).scheme:
            base_id = artifact.get("uriBaseId")
            if base_id is None:
                break
            if not isinstance(base_id, str):
                raise ValueError("SARIF uriBaseId must be a string")
            if base_id in seen:
                raise ValueError(f"Cyclic SARIF URI base: {base_id!r}")
            seen.add(base_id)
            artifact = as_dict(bases.get(base_id))
            base_uri = artifact.get("uri")
            if not artifact:
                # A producer may leave base URIs for the consumer to configure.
                uri = f"{base_id}:{uri}"
                if relative_uris:
                    raise ValueError(f"Unresolved chained SARIF URI base: {base_id!r}")
                return uri
            if not isinstance(base_uri, str) or not base_uri:
                raise ValueError(f"Invalid SARIF URI base: {base_id!r}")
            relative_uris.append(uri)
            uri = base_uri
        for relative_uri in reversed(relative_uris):
            uri = urljoin(uri, relative_uri)
        return uri

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
