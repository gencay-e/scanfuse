import csv
import fnmatch
import hashlib
import html
import json
import os
import re
import shutil
import sys
import tempfile
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

from jinja2 import ChoiceLoader, Environment, FileSystemLoader

from scanfuse.html_report import render_report_fragment
from scanfuse.models import Finding, Host
from scanfuse.parsers.grype import GrypeParser
from scanfuse.parsers.nikto import NiktoParser
from scanfuse.parsers.nmap import NmapParser
from scanfuse.parsers.nuclei import NucleiParser
from scanfuse.parsers.sarif import SarifParser
from scanfuse.parsers.semgrep import SemgrepParser
from scanfuse.parsers.testssl import TestsslParser
from scanfuse.parsers.zap import ZapParser
from scanfuse.utils import _merge_group, has_surrogates, unique_slug, with_host_observations

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_RANK = {name: len(SEVERITIES) - i for i, name in enumerate(SEVERITIES)}
JSON_SCHEMA_VERSION = 2

_MD_SPECIAL = re.compile(r"([\\`*_\[\]])")


class OutputExistsError(Exception):
    """The output directory already contains files that would be overwritten."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _matches_digest(path: Path, expected: object) -> bool:
    """True if `path` is a regular file whose SHA-256 equals `expected`."""
    if not isinstance(expected, str) or path.is_symlink() or not path.is_file():
        return False
    try:
        return _sha256(path) == expected.lower()
    except OSError:
        return False


# Every character that str.splitlines() and Markdown renderers (a lone CR) treat as a line break.
_LINE_BREAKS = re.compile(r"\r\n|[\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")


def _unify_line_breaks(text: str) -> str:
    """Turn every kind of line break into '\\n', so that the line-start rules below see them."""
    return _LINE_BREAKS.sub("\n", text)


def md_escape(value: object) -> str:
    """Make untrusted text safe for Markdown: it shows as plain text and cannot add HTML,
    links, headings, lists or emphasis."""
    text = _unify_line_breaks("" if value is None else str(value))
    text = html.escape(text, quote=False)
    text = _MD_SPECIAL.sub(r"\\\1", text)
    text = re.sub(r"^(\s*)(#+)", r"\1\\\2", text, flags=re.MULTILINE)
    text = re.sub(r"^(\s*)([+\-])(?=\s|$)", r"\1\\\2", text, flags=re.MULTILINE)
    text = re.sub(r"^(\s*)(\d+)([.)])(?=\s|$)", r"\1\2\\\3", text, flags=re.MULTILINE)
    text = re.sub(r"^(\s*)(=+|-{2,})\s*$", r"\1\\\2", text, flags=re.MULTILINE)
    return text


_LIST_ITEM = re.compile(r"(?:[*+-]|\d+[.)])\s")


def _separate_lists(text: str) -> str:
    """Put a blank line before and after a list, so that Markdown does not join it with the
    paragraph above or below. Items of one list stay together."""
    out: list[str] = []
    in_list = False
    for line in text.split("\n"):
        is_item = bool(_LIST_ITEM.match(line))
        if line and is_item != in_list and out and out[-1] != "":
            out.append("")
        out.append(line)
        in_list = is_item if line else False
    return "\n".join(out)


def md_text(value: object) -> str:
    """For longer scanner text (description, remediation): raw HTML is escaped, Markdown
    formatting such as emphasis, code and links is kept, but the text cannot start a heading,
    so it cannot fake a section of the report."""
    text = _unify_line_breaks("" if value is None else str(value))
    # Split text by fenced code blocks (```...```) to preserve code indentation.
    fence = re.compile(r"^(?P<fence>`{3,}|~{3,})(?![`~])[^\n]*\n[\s\S]*?^(?P=fence)[ \t]*$", re.MULTILINE)
    parts: list[tuple[str, bool]] = []
    offset = 0
    for match in fence.finditer(text):
        parts.extend(((text[offset:match.start()], False), (match.group(), True)))
        offset = match.end()
    parts.append((text[offset:], False))
    result = []
    for part, is_code in parts:
        if is_code:
            # Inside fenced code block: preserve indentation
            result.append(part)
        else:
            # Outside code blocks: strip leading blanks so indented lines don't become 4-space code blocks
            p = re.sub(r"^[ \t]+", "", html.escape(part, quote=False), flags=re.MULTILINE)
            p = _separate_lists(p)
            p = re.sub(r"^(\s*)(#+)", r"\1\\\2", p, flags=re.MULTILINE)
            p = re.sub(r"^(\s*)(=+|-{2,})\s*$", r"\1\\\2", p, flags=re.MULTILINE)
            result.append(p)
    return "".join(result)


def md_reference(value: str) -> str:
    """Keep HTTP references clickable without allowing Markdown or HTML injection."""
    from urllib.parse import quote, urlsplit
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
            return "<" + quote(value, safe=":/?#[]@!$&'()*+,;=%") + ">"
    except ValueError:
        pass
    return md_escape(" ".join(value.split()))


def code_fence(data: object) -> str:
    """A backtick fence that is longer than any run of backticks inside `data`."""
    longest = max((len(run) for run in re.findall(r"`+", str(data))), default=0)
    return "`" * max(3, longest + 1)


def csv_safe(cell: object) -> str:
    """Neutralize spreadsheet formulas. Looks at the text after Unicode normalization, so that
    full-width '＝', leading control characters, or a leading no-break space do not get through."""
    val = "" if cell is None else str(cell)
    if not val:
        return val
    probe = unicodedata.normalize("NFKC", val)
    idx = 0
    while idx < len(probe) and (probe[idx].isspace() or unicodedata.category(probe[idx]).startswith("C") or probe[idx] in "\ufeff\u200b\u200c\u200d\u2060\u00a0"):
        idx += 1
    probe_stripped = probe[idx:]
    if probe_stripped.startswith(("=", "+", "-", "@")) or val.startswith(("\t", "\r", "\n", " ", "\ufeff")):
        return f"'{val}"
    return val


def _host_label(host: Host) -> str:
    """Host as one name: 'ip (hostname)', the IP, or the host name if the IP is not known."""
    ip = "" if host.ip.lower() == "unknown" else host.ip
    if ip and host.hostname and host.hostname != ip:
        return f"{ip} ({host.hostname})"
    return ip or host.hostname or ""


class ScanfuseEngine:
    def __init__(self, output_dir: str, template_dir: str | None = None):
        self.resolved: list[Finding] = []
        self.output_dir = Path(output_dir).resolve()
        self.custom_template_dir = Path(template_dir).resolve() if template_dir else None

    # ------------------------------------------------------------------ input

    def process_file(self, file_path: str, format_hint: str) -> list[Finding]:
        """
        Determine parser, parse file, and return findings.
        """
        path = Path(file_path)
        if not path.exists():
            raise ValueError(f"File not found: {file_path}")
        if path.is_dir():
            raise ValueError(f"Expected a file but got a directory: {file_path}")

        if format_hint == "auto":
            format_hint = self._detect_format(file_path)

        from scanfuse.parsers.base import BaseParser
        parser: BaseParser
        if format_hint == "nmap":
            parser = NmapParser()
        elif format_hint == "nuclei":
            parser = NucleiParser()
        elif format_hint == "zap":
            parser = ZapParser()
        elif format_hint == "burp":
            from scanfuse.parsers.burp import BurpParser
            parser = BurpParser()
        elif format_hint == "nessus":
            from scanfuse.parsers.nessus import NessusParser
            parser = NessusParser()
        elif format_hint == "trivy":
            from scanfuse.parsers.trivy import TrivyParser
            parser = TrivyParser()
        elif format_hint == "sarif":
            parser = SarifParser()
        elif format_hint == "semgrep":
            parser = SemgrepParser()
        elif format_hint == "grype":
            parser = GrypeParser()
        elif format_hint == "nikto":
            parser = NiktoParser()
        elif format_hint == "testssl":
            parser = TestsslParser()
        else:
            raise ValueError(f"Unknown format: {format_hint}")

        from defusedxml.common import DefusedXmlException
        from pydantic import ValidationError

        from scanfuse.parsers.base import PartialImportError

        def _filter_surrogates(raw_findings: list[Finding]) -> tuple[list[Finding], int]:
            clean: list[Finding] = []
            dropped = 0
            for f in raw_findings:
                if has_surrogates(f.model_dump()):
                    dropped += 1
                else:
                    clean.append(with_host_observations(f))
            return clean, dropped

        try:
            parsed_findings = parser.parse(file_path)
            clean, dropped = _filter_surrogates(parsed_findings)
            if dropped:
                msg = f"{dropped} finding(s) in {file_path} contain invalid Unicode surrogates"
                if clean:
                    raise PartialImportError(msg, clean)
                raise ValueError(msg)
            return clean
        except PartialImportError as e:
            clean, dropped = _filter_surrogates(e.findings)
            if dropped:
                raise PartialImportError(f"{e}; dropped {dropped} finding(s) with invalid Unicode surrogates", clean) from e
            raise PartialImportError(str(e), clean) from e
        except DefusedXmlException as e:
            raise ValueError(
                f"{file_path}: the XML uses entity or DTD declarations, which scanfuse does not "
                f"process for safety ({type(e).__name__})"
            )
        except ValidationError as e:
            raise ValueError(f"Schema validation failed for findings in {file_path}:\n{e}")
        except OSError as e:
            raise ValueError(f"File I/O error reading {file_path}: {e}")

    # Burp puts a long DTD in front of the first tag (the <issues> tag starts after about 3.4 KB),
    # so the start of the file is read generously.
    _DETECT_BYTES = 64 * 1024
    _XML_ROOTS = (
        ("OWASPZAPReport", "zap"),
        ("nmaprun", "nmap"),
        ("issues", "burp"),
        ("NessusClientData_v2", "nessus"),
        ("niktoscan", "nikto"),
    )

    @staticmethod
    def _detect_format(file_path: str) -> str:
        try:
            with open(file_path, "rb") as bf:
                raw_bytes = bf.read(ScanfuseEngine._DETECT_BYTES)
        except OSError as e:
            raise ValueError(f"Could not read {file_path}: {e}")

        header = ""
        if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
            try:
                header = raw_bytes.decode("utf-16")
            except UnicodeDecodeError:
                pass
        if not header:
            try:
                header = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError:
                try:
                    header = raw_bytes.decode("utf-16")
                except UnicodeDecodeError:
                    header = raw_bytes.decode("latin-1", errors="replace")
        start = header.lstrip()
        if re.match(r'"?Nikto\s+-\s+v[0-9]', start, re.IGNORECASE):
            return "nikto"
        if start.startswith("<"):
            from defusedxml import ElementTree
            from defusedxml.common import DefusedXmlException
            root = None
            try:
                with open(file_path, "rb") as stream:
                    root = next(ElementTree.iterparse(stream, events=("start",)))[1].tag
            except (ElementTree.ParseError, DefusedXmlException, StopIteration):
                pass
            for tag, name in ScanfuseEngine._XML_ROOTS:
                if root == tag:
                    return name
            raise ValueError(
                f"Could not detect the format of {file_path}: unknown XML root element. Use --format."
            )
        if start.startswith(("{", "[")):
            # Read the first JSONL record alone; pretty JSON needs the full document.
            encoding = "utf-16" if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
            try:
                with open(file_path, encoding=encoding) as stream:
                    first_line = next((line for line in stream if line.strip()), "")
                    try:
                        data = json.loads(first_line)
                    except json.JSONDecodeError:
                        stream.seek(0)
                        data = json.load(stream)
            except (OSError, UnicodeError, json.JSONDecodeError):
                return "nuclei"
            if isinstance(data, dict):
                if data.get("version") == "2.1.0" and isinstance(data.get("runs"), list):
                    return "sarif"
                if isinstance(data.get("scanResult"), list):
                    return "testssl"
                matches = data.get("matches")
                if isinstance(matches, list) and (not matches or any(
                    isinstance(item, dict) and "vulnerability" in item for item in matches
                )):
                    return "grype"
                if "SchemaVersion" in data:
                    return "trivy"
                if isinstance(data.get("vulnerabilities"), list) and any(
                    key in data for key in ("host", "ip", "port", "banner")
                ):
                    return "nikto"
                results = data.get("results")
                if isinstance(results, list) and (not results or any(isinstance(item, dict) and "check_id" in item for item in results)):
                    return "semgrep"
                if "findingSeverity" in data and "id" in data:
                    return "testssl"
            elif isinstance(data, list):
                entries = [item for item in data if isinstance(item, dict)]
                if any("Target" in item and any(key in item for key in
                       ("Vulnerabilities", "Misconfigurations", "Secrets", "Class")) for item in entries):
                    return "trivy"
                if any("vulnerabilities" in item and any(key in item for key in ("host", "ip", "port"))
                       for item in entries):
                    return "nikto"
                if any("id" in item and "severity" in item and "finding" in item for item in entries):
                    return "testssl"
            return "nuclei"
        raise ValueError(f"Could not detect the format of {file_path}. Use --format.")

    # ---------------------------------------------------------------- filters

    def filter_by_host(self, findings: list[Finding], host_filter: str) -> list[Finding]:
        """Keep the findings that affect the host. Run this on the parsed findings, before they are
        merged, so that severity, CVSS and sources of a merged finding come only from the selected hosts."""
        # Exact match on IP or host name (ignoring case). '*' and '?' are wildcards.
        pattern = host_filter.lower()
        norm_pattern = pattern.strip("[]")

        def match_host(h: Host) -> bool:
            h_ip = h.ip.lower()
            norm_ip = h_ip.strip("[]")
            if norm_ip and norm_ip != "unknown" and (fnmatch.fnmatchcase(h_ip, pattern) or (norm_pattern and fnmatch.fnmatchcase(norm_ip, norm_pattern))):
                return True
            h_name = (h.hostname or "").lower()
            norm_name = h_name.strip("[]")
            return bool(h.hostname and (fnmatch.fnmatchcase(h_name, pattern) or (norm_pattern and fnmatch.fnmatchcase(norm_name, norm_pattern))))

        # Filter out findings that don't affect the host. Inside the others, keep only the
        # matching hosts and the observations and evidence that belong to them. Evidence
        # that names no host (a finding that was not merged and has several hosts) stays.
        new_filtered = []
        for f in findings:
            matching_hosts = [h for h in f.hosts if match_host(h)]
            if matching_hosts:
                names = {
                    name.strip().lower().strip("[]")
                    for h in matching_hosts for name in (h.ip, h.hostname) if name and name.lower() != "unknown"
                }
                f_copy = f.model_copy()
                f_copy.hosts = matching_hosts
                f_copy.observations = [
                    o for o in f.observations if o.host is None or o.host.lower().strip("[]") in names
                ]
                f_copy.evidence = [
                    e.model_copy(update={"hosts": [x for x in e.hosts if x.strip().lower().strip("[]") in names]})
                    for e in f.evidence
                    if not e.hosts or any(x.strip().lower().strip("[]") in names for x in e.hosts)
                ]
                if f.sources and all(source.hosts is not None for source in f.sources):
                    originals = [Finding.model_validate(source.model_dump()) for source in f.sources]
                    # A merged host can supply an alias absent from an individual source.
                    def match_source_host(host: Host) -> bool:
                        ip = host.ip.strip().lower().strip("[]")
                        name = (host.hostname or "").strip().lower()
                        return match_host(host) or (
                            not name and ip not in ("", "unknown") and ip in names
                        ) or (ip in ("", "unknown") and bool(name) and name in names)

                    selected = []
                    for original in originals:
                        hosts = [h for h in original.hosts if match_source_host(h)]
                        if hosts:
                            selected.append(original.model_copy(update={"hosts": hosts}))
                    if selected:
                        summary = _merge_group(selected)
                        previous = _merge_group(originals)
                        for field in ("title", "severity", "cvss_score", "cvss_vector", "description", "remediation",
                                      "identifiers", "references", "cvss_merge_conflict"):
                            # Keep explicit changes made after the original merge (e.g. overrides).
                            if getattr(f, field) == getattr(previous, field):
                                setattr(f_copy, field, getattr(summary, field))
                        kept_tags = set(summary.tags)
                        original_tags = set(previous.tags)
                        f_copy.tags = [tag for tag in f.tags if tag in kept_tags or tag not in original_tags]
                        f_copy.sources = summary.sources
                        f_copy.source_tool = summary.source_tool
                new_filtered.append(f_copy)
        return new_filtered

    def filter_findings(self, findings: list[Finding], min_severity: str | None = None, ignore_rules: list[str] | None = None) -> list[Finding]:
        filtered = findings

        if ignore_rules:
            if isinstance(ignore_rules, str):
                ignore_rules = [ignore_rules]
            ignore_lower = [str(r).strip().lower() for r in ignore_rules if str(r).strip()]
            if ignore_lower:
                def is_ignored(title: str) -> bool:
                    t_lower = title.lower()
                    return any(rule in t_lower for rule in ignore_lower)
                filtered = [f for f in filtered if not is_ignored(f.title)]

        if min_severity:
            wanted = {s.lower(): s for s in SEVERITIES}.get(min_severity.lower())
            if wanted is None:
                raise ValueError(
                    f"Unknown severity '{min_severity}'. Use one of: {', '.join(SEVERITIES)}"
                )
            min_level = SEVERITY_RANK[wanted]
            filtered = [f for f in filtered if SEVERITY_RANK.get(f.severity, 1) >= min_level]

        return filtered

    # ----------------------------------------------------------------- output

    def _publish(self, kind: str, produce: Callable[[Path], list[str]], replace: bool) -> list[str]:
        """Write a report so that an existing report is never overwritten by accident and is kept
        intact if writing fails.

        `produce(staging_dir)` writes all files into a private staging directory and returns
        their names. Only after that succeeded, the files are moved into the output directory.
        Without `replace`, existing files with the same names abort the export. With `replace`,
        they are overwritten and files of an earlier export of the same kind that are no longer
        part of the report are removed. A stale file is removed only if its SHA-256 still matches
        the digest in the manifest. The manifest is not authenticated, so this is a check against
        changed files, not proof that scanfuse wrote a file.
        """
        if self.output_dir.exists() and not self.output_dir.is_dir():
            raise OSError(f"Output path exists and is not a directory: {self.output_dir}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".scanfuse-staging-", dir=self.output_dir))
        keep_staging = False
        try:
            names = produce(staging)
            existing = sorted(n for n in names if (self.output_dir / n).exists())
            if existing and not replace:
                shown = ", ".join(existing[:5]) + (" ..." if len(existing) > 5 else "")
                raise OutputExistsError(
                    f"{len(existing)} file(s) already exist in {self.output_dir} ({shown}). "
                    "Use --replace to overwrite them, or choose another output directory."
                )

            manifest = self.output_dir / f".scanfuse-manifest-{kind}.json"
            old_names: list[str] = []
            old_digests: dict[str, Any] = {}
            if manifest.exists():
                try:
                    old = json.loads(manifest.read_text(encoding="utf-8"))
                    old_names = list(old.get("files", []))
                    if isinstance(old.get("sha256"), dict):
                        old_digests = old["sha256"]
                except (OSError, ValueError, AttributeError, TypeError, RecursionError):
                    old_names = []

            staged_manifest = staging / manifest.name
            digests = {name: _sha256(staging / name) for name in sorted(names)}
            staged_manifest.write_text(
                json.dumps({"files": sorted(names), "sha256": digests}, indent=2), encoding="utf-8"
            )
            # A stale file is removed only if its digest still matches the manifest (which is
            # not authenticated). Entries without a digest (manifest of scanfuse 1.0.2 or earlier) are left in place.
            stale_names = sorted(
                name for name in {name for name in old_names if isinstance(name, str)} - set(names)
                if replace and isinstance(name, str) and name
                and Path(name).name == name and not name.startswith(".")
                and _matches_digest(self.output_dir / name, old_digests.get(name))
            )
            affected = list(dict.fromkeys([*names, manifest.name, *stale_names]))
            backup = staging / "backup"
            backup.mkdir()
            originals = set()
            for name in affected:
                target = self.output_dir / name
                if target.exists():
                    shutil.copy2(target, backup / name)
                    originals.add(name)

            try:
                for name in names:
                    os.replace(staging / name, self.output_dir / name)
                os.replace(staged_manifest, manifest)
                for name in stale_names:
                    (self.output_dir / name).unlink(missing_ok=True)
            except Exception:
                try:
                    for name in affected:
                        target = self.output_dir / name
                        if name in originals:
                            shutil.copy2(backup / name, target)
                        else:
                            target.unlink(missing_ok=True)
                except Exception as rollback_error:
                    keep_staging = True
                    raise OSError(f"Report recovery failed; backups retained in {backup}") from rollback_error
                raise
            return names
        finally:
            if not keep_staging:
                shutil.rmtree(staging, ignore_errors=True)

    def _template_env(self) -> Environment:
        if hasattr(sys, '_MEIPASS'):
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            base_dir = Path(sys._MEIPASS) / "scanfuse"
        else:
            base_dir = Path(__file__).parent

        builtin_template_dir = base_dir / "templates"

        # Support fallback to builtins if custom template is missing
        loaders: list[FileSystemLoader] = []
        if self.custom_template_dir and self.custom_template_dir.exists():
            loaders.append(FileSystemLoader(str(self.custom_template_dir)))
        loaders.append(FileSystemLoader(str(builtin_template_dir)))

        env = Environment(loader=ChoiceLoader(loaders), autoescape=False)
        env.filters['md'] = md_escape
        env.filters['mdtext'] = md_text
        env.filters['singleline'] = lambda value: ' '.join(str(value).split())
        env.filters['fence'] = code_fence
        env.filters['reference'] = md_reference
        return env

    def export_findings(self, findings: list[Finding], errors: list[dict[str, str]] | None = None,
                        replace: bool = False) -> list[str]:
        """
        Export findings to markdown files using Jinja2 templates, plus index.md and report.html.
        `errors` lists inputs that could not be read; the report is then marked as incomplete.
        """
        errors = errors or []
        env = self._template_env()
        finding_template = env.get_template("finding.md.j2")
        index_template = env.get_template("index.md.j2")

        def produce(staging: Path) -> list[str]:
            names: list[str] = []
            rendered_findings = []
            slugs_seen: set[str] = set()
            for finding in findings:
                finding.slug = unique_slug(finding.title, slugs_seen)
                content = finding_template.render(finding=finding)
                (staging / f"{finding.slug}.md").write_text(content, encoding="utf-8")
                names.append(f"{finding.slug}.md")
                rendered_findings.append(content)

            by_severity = sorted(
                findings, key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.title.casefold())
            )
            index_content = index_template.render(
                findings=findings, findings_sorted=by_severity, errors=errors,
                complete=not errors, resolved=self.resolved,
            ).rstrip() + "\n"
            (staging / "index.md").write_text(index_content, encoding="utf-8")
            names.append("index.md")

            # Generate standalone HTML
            try:
                html_text = self._render_html(index_content, findings, rendered_findings)
                (staging / "report.html").write_text(html_text, encoding="utf-8")
                names.append("report.html")
            except ImportError:
                pass  # Markdown module not installed
            return names

        return self._publish("markdown", produce, replace)

    @staticmethod
    def _render_html(index_content: str, findings: list[Finding], rendered: list[str]) -> str:
        finding_slugs = {finding.slug for finding in findings if finding.slug}
        index_html = render_report_fragment(index_content, finding_slugs=finding_slugs)
        finding_htmls = []
        for finding, content in zip(findings, rendered):
            html_c = render_report_fragment(content, finding_slugs=finding_slugs)
            clean_title = html.escape(
                " ".join([finding.title, *finding.affected()]).strip().lower(), quote=True
            )
            # Add an id corresponding to the slug for the anchor links
            finding_htmls.append(f'<div id="{finding.slug}" class="finding-block" data-severity="{finding.severity}" data-title="{clean_title}"><hr>\n{html_c}</div>')

        html_body = index_html + "\n" + "\n".join(finding_htmls)

        out = "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='utf-8'>\n"
        out += "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        out += "<meta name='color-scheme' content='light dark'>\n"
        out += "<title>Pentest Report</title>\n"
        # The report stays usable without JavaScript and follows the system by default.
        out += """<style>
:root { --fg: #24292f; --bg: #ffffff; --muted-bg: #f6f8fa; --border: #d0d7de; --head-bg: #eaeef2; --link: #0969da; }
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) { --fg: #e6edf3; --bg: #0d1117; --muted-bg: #161b22; --border: #30363d; --head-bg: #21262d; --link: #4493f8; }
}
:root[data-theme="dark"] { --fg: #e6edf3; --bg: #0d1117; --muted-bg: #161b22; --border: #30363d; --head-bg: #21262d; --link: #4493f8; color-scheme: dark; }
:root[data-theme="light"] { color-scheme: light; }
@media print {
  :root { --fg: #24292f !important; --bg: #ffffff !important; --muted-bg: #f6f8fa !important; --border: #d0d7de !important; --head-bg: #eaeef2 !important; --link: #0969da !important; color-scheme: light !important; }
  .filter-bar { display: none !important; }
}
body { font-family: system-ui, sans-serif; margin: 40px auto; max-width: 900px; padding: 0 12px; line-height: 1.6; color: var(--fg); background: var(--bg); overflow-wrap: anywhere; }
a { color: var(--link); }
table { border-collapse: collapse; width: 100%; margin: 20px 0; }
th, td { border: 1px solid var(--border); padding: 8px; text-align: left; }
th { background-color: var(--head-bg); }
pre { background: var(--muted-bg); padding: 15px; overflow-x: auto; border: 1px solid var(--border); }
code { background: var(--muted-bg); }
hr { margin: 40px 0; border: 0; border-top: 2px solid var(--border); }
.filter-bar { padding: 15px; background: var(--muted-bg); border: 1px solid var(--border); margin-bottom: 20px; border-radius: 4px; display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.filter-bar input, .filter-bar select { padding: 8px; border: 1px solid var(--border); border-radius: 4px; background: var(--bg); color: var(--fg); }
"""
        out += "</style>\n</head>\n<body>\n"

        # Inject Filter Bar
        out += """
<div class="filter-bar">
  <input type="text" id="searchTitle" placeholder="Search by title or location..." aria-label="Search by title or location">
  <select id="filterSeverity" aria-label="Filter by severity">
    <option value="All">All Severities</option>
    <option value="Critical">Critical</option>
    <option value="High">High</option>
    <option value="Medium">Medium</option>
    <option value="Low">Low</option>
    <option value="Info">Info</option>
  </select>
  <label for="reportTheme">Theme</label>
  <select id="reportTheme">
    <option value="system">System</option>
    <option value="light">Light</option>
    <option value="dark">Dark</option>
  </select>
</div>
<script>
const themeSelector = document.getElementById('reportTheme');
const themeKey = 'scanfuse.report.theme';
function applyTheme(value) {
  if (value === 'light' || value === 'dark') document.documentElement.dataset.theme = value;
  else delete document.documentElement.dataset.theme;
}
try {
  const savedTheme = localStorage.getItem(themeKey);
  if (savedTheme === 'light' || savedTheme === 'dark') themeSelector.value = savedTheme;
} catch (_) { /* Storage may be unavailable for local files. */ }
applyTheme(themeSelector.value);
themeSelector.addEventListener('change', () => {
  applyTheme(themeSelector.value);
  try {
    if (themeSelector.value === 'system') localStorage.removeItem(themeKey);
    else localStorage.setItem(themeKey, themeSelector.value);
  } catch (_) { /* The selection still works for this report. */ }
});
document.getElementById('searchTitle').addEventListener('input', filterFindings);
document.getElementById('filterSeverity').addEventListener('change', filterFindings);
function filterFindings() {
  const search = document.getElementById('searchTitle').value.toLowerCase();
  const sev = document.getElementById('filterSeverity').value;
  document.querySelectorAll('.finding-block').forEach(el => {
    const titleMatch = el.getAttribute('data-title').includes(search);
    const sevMatch = sev === 'All' || el.getAttribute('data-severity') === sev;
    el.style.display = (titleMatch && sevMatch) ? 'block' : 'none';
  });
}
</script>
"""
        out += html_body
        out += "\n</body>\n</html>"
        return out

    def export_json(self, findings: list[Finding], errors: list[dict[str, str]] | None = None,
                    replace: bool = False) -> list[str]:
        """Export findings to report.json.

        Format (schema_version 2): an object with `schema_version`, `complete` (false if an input
        could not be read), `errors` and `findings`. Version 1 was a bare list of findings.
        Each finding has `observations`: host, method, location and source tool per place where
        a tool saw it.
        """
        errors = errors or []

        def produce(staging: Path) -> list[str]:
            data: dict[str, Any] = {
                "schema_version": JSON_SCHEMA_VERSION,
                "complete": not errors,
                "errors": errors,
                "findings": [f.model_dump() for f in findings],
                "resolved": [f.model_dump() for f in self.resolved],
            }
            (staging / "report.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
            return ["report.json"]

        return self._publish("json", produce, replace)

    def export_csv(self, findings: list[Finding], errors: list[dict[str, str]] | None = None,
                   replace: bool = False, excel: bool = False) -> list[str]:
        """Export findings to a flat CSV file.

        Every row carries an 'Import Status' ('complete' or 'incomplete') so that a partial run
        is visible in the file itself. With `excel`, the file starts with a UTF-8 byte order
        mark and uses ';' as separator, which German-language Excel expects.
        """
        errors = errors or []
        status = "complete" if not errors else f"incomplete ({len(errors)} input error(s))"

        def produce(staging: Path) -> list[str]:
            encoding = "utf-8-sig" if excel else "utf-8"
            with open(staging / "report.csv", "w", newline="", encoding=encoding) as f:
                writer = csv.writer(f, delimiter=";" if excel else ",")
                # The first eight columns keep the order of scanfuse 0.1. New columns come last.
                writer.writerow(["Title", "Severity", "CVSS", "Hosts", "Source Tool", "Description",
                                 "Remediation", "Evidence", "CVSS Vector", "Port", "Identifiers",
                                 "References", "Other Reports", "Import Status", "Affected", "Retest Status"])
                for finding in findings:
                    hosts_str = ", ".join(
                        f"{h.ip} ({h.hostname})" if h.hostname else h.ip for h in finding.hosts
                    )
                    cvss_str = str(finding.cvss_score) if finding.cvss_score is not None else ""
                    evidence_str = "\n---\n".join(
                        f"{e.type}{f' [{e.source}]' if e.source else ''}:\n"
                        + (f"{e.data}\n{e.code}" if e.code else e.data)
                        for e in finding.evidence
                    )
                    others = "\n---\n".join(
                        f"{s.source_tool} | {s.severity}"
                        f"{f' | CVSS {s.cvss_score}' if s.cvss_score is not None else ''}"
                        f"{f' {s.cvss_vector}' if s.cvss_vector else ''}\n"
                        f"{s.description}"
                        f"{f' Remediation: {s.remediation}' if s.remediation else ''}"
                        for s in finding.sources
                    )
                    writer.writerow([csv_safe(v) for v in [
                        finding.title, finding.severity, cvss_str, hosts_str, finding.source_tool,
                        finding.description, finding.remediation, evidence_str,
                        finding.cvss_vector, finding.port, ", ".join(finding.identifiers),
                        "\n".join(finding.references), others, status,
                        "\n".join(finding.affected()), finding.status or "",
                    ]])
            return ["report.csv"]

        return self._publish("csv", produce, replace)

    def export_sarif(self, findings: list[Finding], errors: list[dict[str, str]] | None = None,
                     replace: bool = False) -> list[str]:
        """Export findings as a SARIF 2.1.0 log."""
        errors = errors or []

        def produce(staging: Path) -> list[str]:
            rules: dict[str, dict[str, object]] = {}
            results: list[dict[str, object]] = []
            used_rule_ids: set[str] = set()
            for finding in findings:
                if finding.identifiers:
                    base_rule_id = finding.identifiers[0]
                    rule_id = base_rule_id
                    suffix = 1
                    while rule_id in used_rule_ids:
                        rule_id = f"{base_rule_id}-{suffix}"
                        suffix += 1
                    used_rule_ids.add(rule_id)
                else:
                    rule_id = unique_slug(finding.title, used_rule_ids)
                rule_properties: dict[str, object] = {
                    "identifiers": finding.identifiers,
                    "references": finding.references,
                    "remediation": finding.remediation,
                    "scanfuse-severity": finding.severity,
                }
                if finding.cvss_score is not None:
                    rule_properties["security-severity"] = str(finding.cvss_score)
                rule: dict[str, object] = {
                    "id": rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "properties": rule_properties,
                }
                if finding.references:
                    rule["helpUri"] = finding.references[0]
                rules.setdefault(rule_id, rule)
                result_properties: dict[str, object] = {
                    **finding.model_dump(),
                    "scanfuse-finding-version": 1,
                    "identifiers": finding.identifiers,
                    "references": finding.references,
                    "remediation": finding.remediation,
                    "scanfuse-severity": finding.severity,
                    "port": finding.port,
                    "hosts": [h.model_dump(exclude_none=True) for h in finding.hosts],
                    "observations": [o.model_dump() for o in finding.observations],
                    "evidence": [e.model_dump() for e in finding.evidence],
                }
                if finding.cvss_score is not None:
                    result_properties["security-severity"] = str(finding.cvss_score)
                result: dict[str, object] = {
                    "ruleId": rule_id,
                    "level": {"Critical": "error", "High": "error", "Medium": "warning",
                              "Low": "note", "Info": "note"}.get(finding.severity, "warning"),
                    "message": {"text": finding.title.replace("{", "{{").replace("}", "}}")},
                    "properties": result_properties,
                }
                # A host is not a file, so there is no physicalLocation. Hosts are logical locations.
                logical = [
                    {"name": label, "kind": "resource"}
                    for label in dict.fromkeys(_host_label(host) for host in finding.hosts)
                    if label
                ]
                if logical:
                    result["locations"] = [{"logicalLocations": [item]} for item in logical]
                results.append(result)
            data: dict[str, object] = {
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": {"driver": {"name": "scanfuse", "rules": list(rules.values())}},
                    "results": results,
                    "invocations": [{"executionSuccessful": not errors}],
                }],
            }
            (staging / "report.sarif").write_text(json.dumps(data, indent=2), encoding="utf-8")
            return ["report.sarif"]

        return self._publish("sarif", produce, replace)

    def export_pdf(self, findings: list[Finding], errors: list[dict[str, str]] | None = None,
                   replace: bool = False) -> list[str]:
        from scanfuse.reporters.pdf import export_pdf
        return export_pdf(self.output_dir, findings, errors=errors, replace=replace, resolved=self.resolved)
