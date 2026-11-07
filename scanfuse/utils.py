import re

from scanfuse.models import Evidence, Finding, Host, SourceRecord

# Names that must not be used as a file name on Windows, plus the files scanfuse writes itself.
RESERVED_SLUGS = frozenset(
    {"index", "report", "con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)

SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

# Identifiers that name the same weakness in every tool. Only these (together with title and
# port) decide whether two findings are the same. Tool ids like 'nessus-plugin:123' do not.
_GLOBAL_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[0-9a-z]{4}){3})$", re.IGNORECASE)


def slugify(text: str) -> str:
    """
    Convert text to a safe, lower-cased filename slug.
    Example: 'SQL Injection (Time-based)' -> 'sql-injection-time-based'
    """
    text = text.lower()
    text = re.sub(r'[^a-z0-9]+', '-', text)
    result = text[:100].strip('-')
    return result if result else "unknown-finding"


def unique_slug(title: str, seen: set[str]) -> str:
    """Return a slug that is not in `seen` and is not a reserved file name. Adds it to `seen`."""
    base = slugify(title)
    slug = base
    counter = 1
    while slug in seen or slug in RESERVED_SLUGS:
        slug = f"{base}-{counter}"
        counter += 1
    seen.add(slug)
    return slug


def _global_ids(f: Finding) -> frozenset[str]:
    return frozenset(i.upper() for i in f.identifiers if _GLOBAL_ID.match(i))


def _local_ids(f: Finding) -> dict[str, frozenset[str]]:
    """Tool specific ids grouped by prefix, e.g. {'nessus-plugin': {'12345'}}."""
    grouped: dict[str, set[str]] = {}
    for ident in f.identifiers:
        if ":" in ident:
            prefix, _, value = ident.partition(":")
            grouped.setdefault(prefix, set()).add(value)
    return {k: frozenset(v) for k, v in grouped.items()}


def _identity(f: Finding) -> tuple[str, frozenset[str], str | None]:
    return (f.title.strip().casefold(), _global_ids(f), f.port)


def _compatible(group_ids: dict[str, frozenset[str]], f: Finding) -> bool:
    """Two findings of the same tool with different tool ids are different findings."""
    for prefix, values in _local_ids(f).items():
        if prefix in group_ids and group_ids[prefix] != values:
            return False
    return True


def _record(f: Finding) -> SourceRecord:
    return SourceRecord(
        source_tool=f.source_tool, title=f.title, severity=f.severity,
        cvss_score=f.cvss_score, cvss_vector=f.cvss_vector, description=f.description,
        remediation=f.remediation, identifiers=list(f.identifiers), port=f.port,
    )


def _merge_os(existing: str | None, new: str | None) -> str | None:
    if not existing:
        return new
    if not new or new == existing or new in existing.split(" / "):
        return existing
    return f"{existing} / {new}"


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Merge findings that are the same finding reported more than once.

    Two findings are the same if their titles are equal (ignoring case and surrounding space),
    they carry the same CVE/GHSA ids, they have the same port, and they do not carry different
    ids of the same tool. Similar but not equal titles are never merged.

    A merged finding keeps every host and every piece of evidence. Evidence is tagged with the
    tool that reported it. The description, remediation, severity and CVSS data of every
    original finding stay available in `sources`. The input objects are not modified. The order
    follows the first occurrence of each finding.
    """
    # Each group: [merged finding, tool ids, originals]
    groups: list[list] = []
    by_identity: dict[tuple[str, frozenset[str], str | None], list[int]] = {}

    for f in findings:
        key = _identity(f)
        target = None
        for idx in by_identity.get(key, ()):
            if _compatible(groups[idx][1], f):
                target = groups[idx]
                break
        if target is None:
            by_identity.setdefault(key, []).append(len(groups))
            groups.append([f, dict(_local_ids(f)), [f]])
        else:
            target[2].append(f)
            for prefix, values in _local_ids(f).items():
                target[1].setdefault(prefix, values)

    result: list[Finding] = []
    for first, _ids, originals in groups:
        if len(originals) == 1:
            result.append(first)
        else:
            result.append(_merge_group(originals))
    return result


def _merge_group(originals: list[Finding]) -> Finding:
    base = originals[0].model_copy(deep=True)
    base.sources = [_record(f) for f in originals]

    tools: list[str] = []
    for f in originals:
        for tool in f.source_tool.split(","):
            tool = tool.strip()
            if tool and tool not in tools:
                tools.append(tool)
    base.source_tool = ", ".join(tools)

    host_index: dict[tuple[str, str | None], Host] = {}
    base.hosts = []
    evidence_index: dict[tuple[str, str], Evidence] = {}
    base.evidence = []
    identifiers: list[str] = []

    for f in originals:
        for host in f.hosts:
            key = (host.ip, host.hostname)
            known = host_index.get(key)
            if known is None:
                copy = host.model_copy()
                host_index[key] = copy
                base.hosts.append(copy)
            else:
                known.os = _merge_os(known.os, host.os)
        for ev in f.evidence:
            known_ev = evidence_index.get((ev.type, ev.data))
            tool = ev.source or f.source_tool
            if known_ev is None:
                tagged = ev.model_copy(update={"source": tool})
                evidence_index[(ev.type, ev.data)] = tagged
                base.evidence.append(tagged)
            else:
                # Same evidence from another tool: keep one copy and list every tool.
                tools_seen = (known_ev.source or "").split(", ")
                if tool not in tools_seen:
                    known_ev.source = ", ".join([t for t in tools_seen if t] + [tool])
        for ident in f.identifiers:
            if ident not in identifiers:
                identifiers.append(ident)
    base.identifiers = identifiers
    base.references = list(dict.fromkeys(url for f in originals for url in f.references))

    # Summary values: highest severity, highest CVSS score with its own vector.
    base.severity = max((f.severity for f in originals), key=lambda s: SEVERITY_ORDER.get(s, 0))
    scored = [f for f in originals if f.cvss_score is not None]
    if scored:
        best = max(scored, key=lambda f: f.cvss_score or 0.0)
        base.cvss_score = best.cvss_score
        base.cvss_vector = best.cvss_vector
    else:
        base.cvss_score = None
        base.cvss_vector = next((f.cvss_vector for f in originals if f.cvss_vector), None)
    # Text: first non-empty value; every original text stays in `sources`.
    base.description = next((f.description for f in originals if f.description), base.description)
    base.remediation = next((f.remediation for f in originals if f.remediation), None)
    return base
