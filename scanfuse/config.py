from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from scanfuse.models import Finding


def load_config(path: str | Path = ".scanfuse.yaml") -> dict[str, Any]:
    try:
        value = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("configuration must contain a mapping")
    return value


def apply_overrides(findings: list[Finding], config: dict[str, Any]) -> list[Finding]:
    overrides = config.get("overrides") or []
    if not isinstance(overrides, list):
        raise ValueError("overrides must be a list")
    exclusions = config.get("exclusions") or []
    if not isinstance(exclusions, list):
        raise ValueError("exclusions must be a list")
    result: list[Finding] = []
    for finding in findings:
        if any(_matches(finding, rule) for rule in exclusions if isinstance(rule, dict)):
            continue
        copy = finding.model_copy(deep=True)
        for rule in overrides:
            if not isinstance(rule, dict) or not _matches(copy, rule):
                continue
            severity = rule.get("severity")
            if isinstance(severity, str) and severity in {"Critical", "High", "Medium", "Low", "Info"}:
                copy.severity = severity
            tags = rule.get("tags")
            if isinstance(tags, list):
                copy.tags = sorted(set(copy.tags).union(str(tag) for tag in tags))
        result.append(copy)
    return result


def _matches(finding: Finding, rule: dict[str, Any]) -> bool:
    if "cve" in rule and not any(str(rule["cve"]).casefold() == ident.casefold()
                                 for ident in finding.identifiers):
        return False
    if "tool_id" in rule and not any(str(rule["tool_id"]).casefold() == ident.casefold()
                                     for ident in finding.identifiers):
        return False
    if "port" in rule and str(rule["port"]) != str(finding.port or ""):
        return False
    if "host" in rule and not any(fnmatchcase(host.ip, str(rule["host"])) or
                                  fnmatchcase(host.hostname or "", str(rule["host"]))
                                  for host in finding.hosts):
        return False
    return any(key in rule for key in ("cve", "tool_id", "port", "host"))
