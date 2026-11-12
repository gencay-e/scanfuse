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


def _nonlocal_ids(f: Finding) -> frozenset[str]:
    return frozenset(i.casefold() for i in f.identifiers if ":" not in i)


_Identity = tuple[str, frozenset[str], frozenset[str], str | None, str | None]


def _identity(f: Finding) -> _Identity:
    location = (f.location or "").strip().casefold() or None
    return (f.title.strip().casefold(), _global_ids(f), _nonlocal_ids(f), f.port, location)


def _compatible(
    group_ids: dict[str, frozenset[str]], group_tools: set[str], f: Finding
) -> bool:
    """Two findings of the same tool with different tool ids are different findings."""
    local_ids = _local_ids(f)
    if f.source_tool in group_tools and local_ids != group_ids:
        return False
    for prefix, values in local_ids.items():
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
    they carry the same CVE/GHSA ids, they have the same port, they have the same location
    (URL path and parameter, if the tool gives one), and they do not carry different ids of the
    same tool. Findings without a location only merge with findings without a location.
    Similar but not equal titles are never merged. The same title on different hosts is merged,
    and so are the instances of one scanner alert. The same title at different locations is not.

    A merged finding keeps every host and every piece of evidence. Evidence is tagged with the
    tool that reported it. The description, remediation, severity and CVSS data of every
    original finding stay available in `sources`. The input objects are not modified. The order
    follows the first occurrence of each finding.
    """
    # Each group: [merged finding, tool ids, originals]
    groups: list[list] = []
    by_identity: dict[_Identity, list[int]] = {}

    for f in findings:
        key = _identity(f)
        target = None
        for idx in by_identity.get(key, ()):
            if _compatible(groups[idx][1], groups[idx][3], f):
                target = groups[idx]
                break
        if target is None:
            by_identity.setdefault(key, []).append(len(groups))
            groups.append([f, dict(_local_ids(f)), [f], {f.source_tool}])
        else:
            target[2].append(f)
            target[3].add(f.source_tool)
            for prefix, values in _local_ids(f).items():
                target[1].setdefault(prefix, values)

    result: list[Finding] = []
    for first, _ids, originals, _tools in groups:
        if len(originals) == 1:
            result.append(first)
        else:
            result.append(_merge_group(originals))
    return result


def _merge_group(originals: list[Finding]) -> Finding:
    base = originals[0].model_copy(deep=True)

    unique_sources = []
    seen_sources = set()
    for f in originals:
        rec = _record(f)
        s_key = (rec.source_tool, rec.description, rec.remediation, rec.severity, rec.cvss_score, rec.cvss_vector)
        if s_key not in seen_sources:
            seen_sources.add(s_key)
            unique_sources.append(rec)
    base.sources = unique_sources

    tools: list[str] = []
    for f in originals:
        for tool in f.source_tool.split(","):
            tool = tool.strip()
            if tool and tool not in tools:
                tools.append(tool)
    base.source_tool = ", ".join(tools)

    base.hosts = []
    evidence_index: dict[tuple[str, str], Evidence] = {}
    base.evidence = []
    identifiers: list[str] = []

    for f in originals:
        for host in f.hosts:
            norm_ip = (host.ip or "unknown").strip().lower()
            norm_hn = (host.hostname or "").strip().lower() or None

            match: Host | None = None
            for existing in base.hosts:
                ex_ip = (existing.ip or "unknown").strip().lower()
                ex_hn = (existing.hostname or "").strip().lower() or None

                # 1. Exact match on both IP and hostname
                if ex_ip == norm_ip and ex_hn == norm_hn:
                    match = existing
                    break

                # 2. Same IP, one has no hostname and the other has one -> enrich hostname
                if ex_ip != "unknown" and ex_ip == norm_ip and (ex_hn is None or norm_hn is None):
                    match = existing
                    break

                # 3. Same hostname, one has unknown IP and the other has known IP -> enrich IP
                if norm_hn and ex_hn == norm_hn and (ex_ip == "unknown" or norm_ip == "unknown"):
                    match = existing
                    break

            if match is None:
                copy = host.model_copy()
                base.hosts.append(copy)
            else:
                if not match.hostname and host.hostname:
                    match.hostname = host.hostname
                if (match.ip or "unknown").strip().lower() == "unknown" and norm_ip != "unknown":
                    match.ip = host.ip
                match.os = _merge_os(match.os, host.os)
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

    # Mark CVSS vector conflict if merged findings had different base metrics.
    _CVSS_BASE_KEYS = frozenset({'AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'})

    def _cvss_base_metrics(vec: str | None) -> frozenset[tuple[str, str]]:
        if not vec:
            return frozenset()
        metrics = set()
        for part in vec.split("/"):
            if ":" in part:
                key, value = part.split(":", 1)
                if key in _CVSS_BASE_KEYS:
                    metrics.add((key, value))
        return frozenset(metrics)

    vectors = [f.cvss_vector for f in originals if f.cvss_vector]
    if len(vectors) > 1:
        base_metrics_sets = [_cvss_base_metrics(v) for v in vectors]
        if len(set(base_metrics_sets)) > 1:
            base.cvss_merge_conflict = True

    # Text: first non-empty value; every original text stays in `sources`.
    base.description = next((f.description for f in originals if f.description), base.description)
    base.remediation = next((f.remediation for f in originals if f.remediation), None)
    return base
