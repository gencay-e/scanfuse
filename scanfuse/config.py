from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from scanfuse.models import Finding

SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
ROOT_KEYS = {"ignore_titles", "overrides", "exclusions"}
RULE_KEYS = {"cve", "tool_id", "port", "host", "source_tool", "title", "location", "severity", "tags"}
MATCH_KEYS = RULE_KEYS - {"severity", "tags"}


class StrictSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        result = super().construct_mapping(node, deep=deep)
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in seen:
                raise ValueError(f"duplicate configuration key: {key}")
            seen.add(key)
        return result


def _validate_rule(rule: object, section: str, index: int) -> dict[str, Any]:
    label = f"{section}[{index}]"
    if not isinstance(rule, dict):
        raise ValueError(f"{label} must be a mapping")
    unknown = set(rule) - RULE_KEYS
    if unknown:
        raise ValueError(f"unknown key(s) in {label}: {', '.join(sorted(map(str, unknown)))}")
    if section == "exclusions" and {"severity", "tags"} & rule.keys():
        raise ValueError(f"{label} cannot use severity or tags")
    if not any(key in rule for key in MATCH_KEYS):
        raise ValueError(f"{label} must contain at least one match field")
    for key in MATCH_KEYS:
        if key in rule and (isinstance(rule[key], bool) or not isinstance(rule[key], (str, int))):
            raise ValueError(f"{label}.{key} must be a string")
    if "severity" in rule and (not isinstance(rule["severity"], str) or rule["severity"] not in SEVERITIES):
        raise ValueError(f"{label}.severity must be one of: {', '.join(sorted(SEVERITIES))}")
    if "tags" in rule and (not isinstance(rule["tags"], list) or not all(isinstance(t, str) for t in rule["tags"])):
        raise ValueError(f"{label}.tags must be a list of strings")
    return rule


def validate_config(value: object) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("configuration must contain a mapping")
    unknown = set(value) - ROOT_KEYS
    if unknown:
        raise ValueError(f"unknown configuration key(s): {', '.join(sorted(map(str, unknown)))}")
    result: dict[str, Any] = dict(value)
    titles = result.get("ignore_titles")
    if titles is None:
        result["ignore_titles"] = []
    elif isinstance(titles, str):
        result["ignore_titles"] = [titles.strip()] if titles.strip() else []
    elif titles is not None and (not isinstance(titles, list) or not all(isinstance(t, str) for t in titles)):
        raise ValueError("ignore_titles must be a list of strings")
    if isinstance(result.get("ignore_titles"), list):
        result["ignore_titles"] = [title.strip() for title in result["ignore_titles"] if title.strip()]
    for section in ("overrides", "exclusions"):
        rules = result.get(section, [])
        if rules is None:
            rules = []
        if not isinstance(rules, list):
            raise ValueError(f"{section} must be a list")
        result[section] = [_validate_rule(rule, section, i) for i, rule in enumerate(rules)]
    return result


def load_config(path: str | Path = ".scanfuse.yaml") -> dict[str, Any]:
    try:
        loader = StrictSafeLoader(Path(path).read_text(encoding="utf-8"))
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    return validate_config(value)


def apply_overrides(findings: list[Finding], config: dict[str, Any]) -> list[Finding]:
    config = validate_config(config)
    result: list[Finding] = []
    for finding in findings:
        if any(_matches(finding, rule) for rule in config["exclusions"]):
            continue
        copy = finding.model_copy(deep=True)
        for rule in config["overrides"]:
            if not _matches(copy, rule):
                continue
            if "severity" in rule:
                copy.severity = rule["severity"]
            if "tags" in rule:
                copy.tags = sorted(set(copy.tags).union(rule["tags"]))
        result.append(copy)
    return result


def _text_matches(actual: str, pattern: str, *, insensitive: bool = True) -> bool:
    if insensitive:
        actual, pattern = actual.casefold(), pattern.casefold()
    return fnmatchcase(actual, pattern) if any(c in pattern for c in "*?[") else pattern in actual


def _matches(finding: Finding, rule: dict[str, Any]) -> bool:
    if "cve" in rule and not any(str(rule["cve"]).casefold() == ident.casefold() for ident in finding.identifiers):
        return False
    if "tool_id" in rule and not any(str(rule["tool_id"]).casefold() == ident.casefold() for ident in finding.identifiers):
        return False
    if "port" in rule:
        wanted = str(rule["port"]).strip().casefold()
        actual = str(finding.port or "").strip().casefold()
        if "/" not in wanted and actual.partition("/")[0] == wanted:
            pass
        elif wanted != actual:
            return False
    if "host" in rule and not any(fnmatchcase(host.ip.casefold(), str(rule["host"]).casefold()) or
                                  fnmatchcase((host.hostname or "").casefold(), str(rule["host"]).casefold())
                                  for host in finding.hosts):
        return False
    if "source_tool" in rule and not _text_matches(finding.source_tool, str(rule["source_tool"])):
        return False
    if "title" in rule and not _text_matches(finding.title, str(rule["title"])):
        return False
    if "location" in rule and not any(_text_matches(o.location or "", str(rule["location"]), insensitive=False)
                                      for o in finding.observations):
        return False
    return any(key in rule for key in MATCH_KEYS)
