"""Property-based tests for scanfuse parsers, normalizers, escaping, and deduplication."""

from __future__ import annotations

import json
import re
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
from typing import Literal

from hypothesis import example, given, settings
from hypothesis import strategies as st

from scanfuse.engine import SEVERITY_RANK, code_fence, csv_safe, md_escape, md_text
from scanfuse.models import Evidence, Finding, Host
from scanfuse.parsers.base import (
    clean_ids,
    cve_ids,
    cwe_id,
    cwe_ids_from_text,
    extract_urls,
    html_to_text,
)
from scanfuse.parsers.burp import BurpParser
from scanfuse.parsers.nessus import NessusParser
from scanfuse.parsers.nmap import NmapParser
from scanfuse.parsers.nuclei import NucleiParser
from scanfuse.parsers.trivy import TrivyParser
from scanfuse.parsers.zap import ZapParser
from scanfuse.utils import RESERVED_SLUGS, deduplicate_findings, slugify, unique_slug

# XML 1.0 valid character strategy (excludes control chars except \t, \n, \r and surrogates)
cs_categories: tuple[Literal["Cs"]] = ("Cs",)
xml_text = st.text(
    alphabet=st.characters(
        blacklist_categories=cs_categories,
        blacklist_characters=tuple(chr(c) for c in range(0x00, 0x20) if c not in (0x09, 0x0A, 0x0D))
        + ("\ufffe", "\uffff"),
    ),
    max_size=120,
)

non_empty_xml_text = xml_text.filter(lambda s: bool(s.strip()))


@given(st.text(max_size=200))
def test_slugify_invariants(text: str) -> None:
    slug = slugify(text)
    assert 1 <= len(slug) <= 100
    assert slug == slug.lower()
    assert not slug.startswith("-")
    assert not slug.endswith("-")
    assert all(ch.isalnum() or ch == "-" for ch in slug)
    # Idempotence: slugifying an already slugified string yields the same slug
    assert slugify(slug) == slug


@given(st.lists(st.text(max_size=80), min_size=1, max_size=40))
def test_unique_slug_disjoint_and_never_reserved(titles: list[str]) -> None:
    seen: set[str] = set()
    slugs = [unique_slug(t, seen) for t in titles]
    assert len(slugs) == len(set(slugs))
    for s in slugs:
        assert s not in RESERVED_SLUGS


@given(st.lists(st.one_of(st.none(), st.text(max_size=40)), max_size=30))
def test_clean_ids_preserves_order_and_uniqueness(items: list[str | None]) -> None:
    cleaned = clean_ids(items)
    assert len(cleaned) == len(set(cleaned))
    assert all(isinstance(x, str) and x == x.strip() and len(x) > 0 for x in cleaned)
    # Idempotence
    assert clean_ids(cleaned) == cleaned


@given(
    st.lists(
        st.tuples(
            st.integers(min_value=1999, max_value=2035),
            st.integers(min_value=1000, max_value=9999999),
        ),
        max_size=15,
    )
)
def test_cve_ids_extraction_and_normalization(pairs: list[tuple[int, int]]) -> None:
    raw_tokens = [f"cve-{year}-{num}" for year, num in pairs]
    expected = list(dict.fromkeys(f"CVE-{year}-{num}" for year, num in pairs))
    joined = " ; ".join(raw_tokens)
    assert cve_ids(joined) == expected
    assert cve_ids(raw_tokens) == expected


@given(st.integers(min_value=1, max_value=99999), st.sampled_from(["", "CWE-", "cwe-"]))
def test_cwe_id_valid_positive_numbers(n: int, prefix: str) -> None:
    assert cwe_id(f"{prefix}{n}") == f"CWE-{n}"
    if prefix:
        assert cwe_ids_from_text(f"Found {prefix}{n} in response") == [f"CWE-{n}"]
    else:
        assert cwe_ids_from_text(f"Found {n} in response") == []


@given(st.integers(max_value=0))
def test_cwe_id_rejects_non_positive(n: int) -> None:
    assert cwe_id(str(n)) is None
    assert cwe_id(f"CWE-{n}") is None


@given(st.text(max_size=150), st.text(max_size=80))
def test_html_to_text_strips_scripts_and_styles(visible: str, payload: str) -> None:
    safe_visible = visible.replace("<", "").replace(">", "").replace("&", "")
    safe_payload = payload.replace("<", "").replace(">", "")
    raw = f"<p>{safe_visible}</p><script>{safe_payload}</script><style>{safe_payload}</style>"
    result = html_to_text(raw)
    assert "<script" not in result.lower()
    assert "<style" not in result.lower()
    if safe_payload.strip() and safe_payload.strip() not in safe_visible:
        assert safe_payload.strip() not in result


@given(st.text(max_size=200))
def test_csv_safe_neutralizes_formula_prefixes(cell: str) -> None:
    out = csv_safe(cell)
    if not out:
        return
    if not out.startswith("'"):
        probe = unicodedata.normalize("NFKC", out).lstrip()
        assert not probe.startswith(("=", "+", "-", "@"))
        assert not out.startswith(("\t", "\r", "\n", " "))


@given(st.text(max_size=200))
def test_code_fence_strictly_longer_than_internal_backticks(data: str) -> None:
    fence = code_fence(data)
    assert len(fence) >= 3
    assert set(fence) == {"`"}
    assert fence not in data


_FENCE = re.compile(r"```[^\n]*\n[\s\S]*?\n```")


@example(text="a\r#x")
@example(text="a\x0b#x")
@example(text="a\x85#x")
@example(text="a\u2028#x")
@given(st.text(max_size=200))
def test_md_escape_and_md_text_neutralize_raw_tags_and_headings(text: str) -> None:
    escaped = md_escape(text)
    assert "<" not in escaped
    assert ">" not in escaped
    body = md_text(text)
    assert "<" not in body
    assert ">" not in body
    # Inside a complete code fence the text is literal code and cannot form a heading.
    for line in _FENCE.sub("", body).splitlines():
        assert not line.lstrip().startswith("#")
    for line in escaped.splitlines():
        assert not line.lstrip().startswith("#")


def test_every_line_break_variant_is_neutralized_before_a_heading_marker() -> None:
    for brk in ("\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
        for func in (md_escape, md_text):
            out = func(f"a{brk}# h{brk}- i{brk}1. j{brk}===")
            for line in out.splitlines():
                stripped = line.lstrip()
                assert not stripped.startswith(("#", "===")), (repr(brk), func.__name__, line)
                if func is md_escape:  # md_text keeps lists on purpose
                    assert not stripped.startswith(("- ", "1. ")), (repr(brk), line)


finding_strategy = st.builds(
    Finding,
    title=st.text(min_size=1, max_size=50).filter(lambda s: bool(s.strip())),
    severity=st.sampled_from(["Critical", "High", "Medium", "Low", "Info"]),
    cvss_score=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0, allow_nan=False)),
    cvss_vector=st.one_of(st.none(), st.just("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
    description=st.text(max_size=100),
    remediation=st.one_of(st.none(), st.text(max_size=80)),
    hosts=st.lists(
        st.builds(
            Host,
            ip=st.sampled_from(["10.0.0.1", "10.0.0.2", "192.0.2.5"]),
            hostname=st.one_of(st.none(), st.sampled_from(["app.local", "db.local"])),
            os=st.one_of(st.none(), st.sampled_from(["Linux", "Windows"])),
        ),
        min_size=1,
        max_size=3,
    ),
    evidence=st.lists(
        st.builds(
            Evidence,
            type=st.sampled_from(["http-request", "port-scan", "match"]),
            data=st.text(min_size=1, max_size=60),
        ),
        max_size=3,
    ),
    source_tool=st.sampled_from(["nmap", "nuclei", "zap", "burp", "nessus", "trivy"]),
    identifiers=st.lists(
        st.sampled_from(["CVE-2024-0001", "CVE-2024-0002", "CWE-79", "CWE-89"]),
        max_size=3,
    ),
    references=st.lists(
        st.sampled_from(["https://example.com/a", "https://example.com/b"]),
        max_size=2,
    ),
    port=st.one_of(st.none(), st.sampled_from(["80/tcp", "443/tcp", "22/tcp"])),
)


@given(st.lists(finding_strategy, min_size=1, max_size=15))
@settings(max_examples=50, deadline=None)
def test_deduplicate_findings_preserves_all_hosts_evidence_and_max_severity(
    items: list[Finding],
) -> None:
    merged = deduplicate_findings(items)
    assert 1 <= len(merged) <= len(items)

    input_host_pairs = {(h.ip, h.hostname) for f in items for h in f.hosts}
    output_host_pairs = {(h.ip, h.hostname) for f in merged for h in f.hosts}

    input_ips = {h.ip for f in items for h in f.hosts}
    output_ips = {h.ip for f in merged for h in f.hosts}
    assert input_ips == output_ips
    assert output_host_pairs.issubset(input_host_pairs)
    for ip, hn in input_host_pairs - output_host_pairs:
        assert hn is None
        assert any(out_ip == ip and out_hn is not None for out_ip, out_hn in output_host_pairs)

    input_evidence_pairs = {(e.type, e.data) for f in items for e in f.evidence}
    output_evidence_pairs = {(e.type, e.data) for f in merged for e in f.evidence}
    assert input_evidence_pairs == output_evidence_pairs

    max_in_sev = max(SEVERITY_RANK[f.severity] for f in items)
    max_out_sev = max(SEVERITY_RANK[f.severity] for f in merged)
    assert max_in_sev == max_out_sev


@given(
    template_id=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"),
        min_size=1,
        max_size=30,
    ),
    name=non_empty_xml_text,
    severity=st.sampled_from(["critical", "high", "medium", "low", "info", "unknown", "other"]),
    ip=st.sampled_from(["192.0.2.10", "198.51.100.7"]),
    cvss=st.one_of(st.none(), st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False)),
)
@settings(max_examples=40, deadline=None)
def test_nuclei_parser_roundtrip_properties(
    template_id: str, name: str, severity: str, ip: str, cvss: float | None
) -> None:
    record = {
        "template-id": template_id,
        "info": {
            "name": name,
            "severity": severity,
            "description": "Prop description",
            "classification": {
                "cvss-score": cvss,
                "cve-id": ["CVE-2025-1234"],
                "cwe-id": ["CWE-79"],
            },
        },
        "ip": ip,
        "matched-at": f"https://{ip}/test",
    }
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", encoding="utf-8", delete=False) as tf:
        tf.write(json.dumps(record) + "\n")
        path = tf.name

    findings = NucleiParser().parse(path)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == name
    assert f.hosts[0].ip == ip
    assert f"nuclei-template:{template_id}" in f.identifiers
    assert "CVE-2025-1234" in f.identifiers
    assert "CWE-79" in f.identifiers
    assert f.severity in SEVERITY_RANK


@given(
    vuln_id=st.from_regex(r"CVE-202[0-9]-\d{4,6}", fullmatch=True),
    pkg_name=st.text(
        alphabet=st.characters(whitelist_categories=("Ll", "Nd"), whitelist_characters="-_."),
        min_size=1,
        max_size=25,
    ),
    severity=st.sampled_from(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]),
    title=non_empty_xml_text,
)
@settings(max_examples=40, deadline=None)
def test_trivy_parser_roundtrip_properties(
    vuln_id: str, pkg_name: str, severity: str, title: str
) -> None:
    payload = {
        "SchemaVersion": 2,
        "ArtifactName": "prop-image:latest",
        "Results": [
            {
                "Target": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": vuln_id,
                        "PkgName": pkg_name,
                        "Title": title,
                        "Severity": severity,
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "PrimaryURL": "https://avd.aquasec.com/nvd/" + vuln_id.lower(),
                    }
                ],
            }
        ],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", encoding="utf-8", delete=False) as tf:
        json.dump(payload, tf)
        path = tf.name

    findings = TrivyParser().parse(path)
    assert len(findings) == 1
    f = findings[0]
    assert f.title == title.strip()
    assert vuln_id.upper() in f.identifiers
    assert f.severity in SEVERITY_RANK
    assert f.references == ["https://avd.aquasec.com/nvd/" + vuln_id.lower()]


@given(
    portid=st.integers(min_value=1, max_value=65535),
    proto=st.sampled_from(["tcp", "udp"]),
    service=st.sampled_from(["http", "ssh", "tls", "dns"]),
    product=xml_text,
)
@settings(max_examples=40, deadline=None)
def test_nmap_parser_roundtrip_properties(
    portid: int, proto: str, service: str, product: str
) -> None:
    root = ET.Element("nmaprun")
    host = ET.SubElement(root, "host")
    ET.SubElement(host, "status", state="up")
    ET.SubElement(host, "address", addr="192.0.2.55", addrtype="ipv4")
    ports = ET.SubElement(host, "ports")
    port = ET.SubElement(ports, "port", protocol=proto, portid=str(portid))
    ET.SubElement(port, "state", state="open")
    ET.SubElement(port, "service", name=service, product=product)

    with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as tf:
        tf.write(ET.tostring(root, encoding="utf-8"))
        path = tf.name

    findings = NmapParser().parse(path)
    assert len(findings) == 1
    assert findings[0].port == f"{portid}/{proto}"
    assert findings[0].hosts[0].ip == "192.0.2.55"


@given(
    name=non_empty_xml_text,
    sev_num=st.sampled_from(["0", "1", "2", "3", "4"]),
    port=st.integers(min_value=1, max_value=65535),
    plugin_id=st.integers(min_value=1000, max_value=99999),
)
@settings(max_examples=30, deadline=None)
def test_nessus_burp_zap_xml_parsers_roundtrip(
    name: str, sev_num: str, port: int, plugin_id: int
) -> None:
    clean_name = html_to_text(name) or "Fallback Name"

    # Nessus
    nessus_root = ET.Element("NessusClientData_v2")
    rep = ET.SubElement(nessus_root, "Report")
    rh = ET.SubElement(rep, "ReportHost", name="192.0.2.99")
    ET.SubElement(
        rh,
        "ReportItem",
        port=str(port),
        protocol="tcp",
        pluginID=str(plugin_id),
        pluginName=clean_name,
        severity=sev_num,
    )
    with tempfile.NamedTemporaryFile("wb", suffix=".nessus", delete=False) as tf:
        tf.write(ET.tostring(nessus_root, encoding="utf-8"))
        n_path = tf.name
    n_findings = NessusParser().parse(n_path)
    assert len(n_findings) == 1
    assert f"nessus-plugin:{plugin_id}" in n_findings[0].identifiers
    assert n_findings[0].port == f"{port}/tcp"

    # Burp
    burp_root = ET.Element("issues")
    issue = ET.SubElement(burp_root, "issue")
    ET.SubElement(issue, "name").text = clean_name
    ET.SubElement(issue, "type").text = str(plugin_id)
    ET.SubElement(issue, "severity").text = "High"
    h_elem = ET.SubElement(issue, "host", ip="192.0.2.99")
    h_elem.text = "burp.example"
    with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as tf:
        tf.write(ET.tostring(burp_root, encoding="utf-8"))
        b_path = tf.name
    b_findings = BurpParser().parse(b_path)
    assert len(b_findings) == 1
    assert f"burp-type:{plugin_id}" in b_findings[0].identifiers

    # ZAP
    zap_root = ET.Element("OWASPZAPReport")
    site = ET.SubElement(zap_root, "site", host="192.0.2.99")
    alerts = ET.SubElement(site, "alerts")
    alert = ET.SubElement(alerts, "alertitem")
    ET.SubElement(alert, "name").text = clean_name
    ET.SubElement(alert, "pluginid").text = str(plugin_id)
    ET.SubElement(alert, "riskcode").text = "3"
    with tempfile.NamedTemporaryFile("wb", suffix=".xml", delete=False) as tf:
        tf.write(ET.tostring(zap_root, encoding="utf-8"))
        z_path = tf.name
    z_findings = ZapParser().parse(z_path)
    assert len(z_findings) == 1
    assert f"zap-plugin:{plugin_id}" in z_findings[0].identifiers


@given(st.lists(st.sampled_from(["https://example.com/a", "http://test.local/b?x=1"]), max_size=10))
def test_extract_urls_deduplicates_and_strips_trailing_punctuation(urls: list[str]) -> None:
    decorated = [f"({u})." for u in urls]
    result = extract_urls(decorated)
    assert result == list(dict.fromkeys(urls))
