import csv
import fnmatch
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
from scanfuse.parsers.nmap import NmapParser
from scanfuse.parsers.nuclei import NucleiParser
from scanfuse.parsers.zap import ZapParser
from scanfuse.utils import unique_slug

SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
SEVERITY_RANK = {name: len(SEVERITIES) - i for i, name in enumerate(SEVERITIES)}
INPUT_FORMATS = ("auto", "nmap", "nuclei", "zap", "burp", "nessus", "trivy")
OUTPUT_FORMATS = ("markdown", "json", "csv")
JSON_SCHEMA_VERSION = 2

_MD_SPECIAL = re.compile(r"([\\`*_\[\]])")


class OutputExistsError(Exception):
    """The output directory already contains files that would be overwritten."""


def md_escape(value: object) -> str:
    """Make untrusted text safe for Markdown: it shows as plain text and cannot add HTML,
    links, headings, lists or emphasis."""
    text = "" if value is None else str(value)
    text = html.escape(text, quote=False)
    text = _MD_SPECIAL.sub(r"\\\1", text)
    text = re.sub(r"^(\s*)([#+\-])(?=\s|$)", r"\1\\\2", text, flags=re.MULTILINE)
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
    text = html.escape("" if value is None else str(value), quote=False)
    # Indented lines would become code blocks in Markdown (four spaces). Scanner texts use
    # indentation for layout only, so leading blanks are removed.
    text = re.sub(r"^[ \t]+", "", text, flags=re.MULTILINE)
    text = _separate_lists(text)
    text = re.sub(r"^(\s*)(#+)", r"\1\\\2", text, flags=re.MULTILINE)
    text = re.sub(r"^(\s*)(=+|-{2,})\s*$", r"\1\\\2", text, flags=re.MULTILINE)
    return text


def code_fence(data: object) -> str:
    """A backtick fence that is longer than any run of backticks inside `data`."""
    longest = max((len(run) for run in re.findall(r"`+", str(data))), default=0)
    return "`" * max(3, longest + 1)


def csv_safe(cell: object) -> str:
    """Neutralize spreadsheet formulas. Looks at the text after Unicode normalization, so that
    full-width '＝' or a leading no-break space do not get through."""
    val = "" if cell is None else str(cell)
    if not val:
        return val
    probe = unicodedata.normalize("NFKC", val).lstrip()
    if probe.startswith(("=", "+", "-", "@")) or val.startswith(("\t", "\r", "\n", " ")):
        return f"'{val}"
    return val


class ScanfuseEngine:
    def __init__(self, output_dir: str, template_dir: str | None = None):
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
        else:
            raise ValueError(f"Unknown format: {format_hint}")

        from defusedxml.common import DefusedXmlException
        from pydantic import ValidationError
        try:
            return parser.parse(file_path)
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
    )

    @staticmethod
    def _detect_format(file_path: str) -> str:
        try:
            with open(file_path, encoding="utf-8-sig") as f:
                header = f.read(ScanfuseEngine._DETECT_BYTES)
        except (OSError, UnicodeDecodeError) as e:
            raise ValueError(f"Could not read {file_path}: {e}")
        start = header.lstrip()
        if start.startswith("<"):
            for tag, name in ScanfuseEngine._XML_ROOTS:
                if re.search(rf"<{tag}[\s>/]", header):
                    return name
            raise ValueError(
                f"Could not detect the format of {file_path}: unknown XML root element. Use --format."
            )
        if start.startswith(("{", "[")):
            # Trivy writes either an object with SchemaVersion/ArtifactName (current versions) or,
            # in older versions, a list of results that have a Target.
            is_trivy_object = start.startswith("{") and '"SchemaVersion"' in header and '"ArtifactName"' in header
            is_trivy_list = start.startswith("[") and '"Target"' in header and any(
                f'"{key}"' in header for key in ("Vulnerabilities", "Misconfigurations", "Secrets", "Class")
            )
            return "trivy" if is_trivy_object or is_trivy_list else "nuclei"
        raise ValueError(f"Could not detect the format of {file_path}. Use --format.")

    # ---------------------------------------------------------------- filters

    def filter_findings(self, findings: list[Finding], min_severity: str | None = None, host_filter: str | None = None, ignore_rules: list[str] | None = None) -> list[Finding]:
        filtered = findings

        if ignore_rules:
            if isinstance(ignore_rules, str):
                ignore_rules = [ignore_rules]
            ignore_lower = [str(r).lower() for r in ignore_rules]
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

        if host_filter:
            # Exact match on IP or host name (ignoring case). '*' and '?' are wildcards.
            pattern = host_filter.lower()
            def match_host(h: Host) -> bool:
                if fnmatch.fnmatchcase(h.ip.lower(), pattern):
                    return True
                return bool(h.hostname and fnmatch.fnmatchcase(h.hostname.lower(), pattern))

            # Filter out findings that don't affect the host.
            # Also, filter the hosts list inside the finding so we don't report other hosts.
            new_filtered = []
            for f in filtered:
                matching_hosts = [h for h in f.hosts if match_host(h)]
                if matching_hosts:
                    f_copy = f.model_copy()
                    f_copy.hosts = matching_hosts
                    new_filtered.append(f_copy)
            filtered = new_filtered

        return filtered

    # ----------------------------------------------------------------- output

    def _publish(self, kind: str, produce: Callable[[Path], list[str]], replace: bool) -> list[str]:
        """Write a report so that an existing report is never overwritten by accident and is kept
        intact if writing fails.

        `produce(staging_dir)` writes all files into a private staging directory and returns
        their names. Only after that succeeded, the files are moved into the output directory.
        Without `replace`, existing files with the same names abort the export. With `replace`,
        they are overwritten and files of an earlier export of the same kind that are no longer
        part of the report are removed. Files that scanfuse did not write are never removed.
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
            if manifest.exists():
                try:
                    old_names = list(json.loads(manifest.read_text(encoding="utf-8")).get("files", []))
                except (OSError, ValueError):
                    old_names = []

            staged_manifest = staging / manifest.name
            staged_manifest.write_text(json.dumps({"files": sorted(names)}, indent=2), encoding="utf-8")
            stale_names = sorted(
                name for name in set(old_names) - set(names)
                if replace and isinstance(name, str) and name
                and Path(name).name == name and not name.startswith(".")
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

        env = Environment(loader=ChoiceLoader(loaders), autoescape=False)  # noqa: S701
        env.filters['md'] = md_escape
        env.filters['mdtext'] = md_text
        env.filters['fence'] = code_fence
        return env

    def export_findings(self, findings: list[Finding], errors: list[dict[str, str]] | None = None,
                        replace: bool = False) -> list[str]:
        """
        Export findings to markdown files using Jinja2 templates, plus index.md and report.html.
        `errors` lists inputs that could not be read; the report is then marked as incomplete.
        """
        errors = errors or []
        if not findings:
            return []
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
                complete=not errors,
            )
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
        index_html = render_report_fragment(index_content)
        finding_htmls = []
        for finding, content in zip(findings, rendered):
            html_c = render_report_fragment(content)
            clean_title = html.escape(finding.title.lower(), quote=True)
            # Add an id corresponding to the slug for the anchor links
            finding_htmls.append(f'<div id="{finding.slug}" class="finding-block" data-severity="{finding.severity}" data-title="{clean_title}"><hr>\n{html_c}</div>')

        html_body = index_html + "\n" + "\n".join(finding_htmls)

        out = "<!DOCTYPE html>\n<html>\n<head>\n<meta charset='utf-8'>\n"
        out += "<meta name='viewport' content='width=device-width, initial-scale=1'>\n"
        out += "<meta name='color-scheme' content='light dark'>\n"
        out += "<title>Pentest Report</title>\n"
        # Colours follow the reader's system setting (light or dark).
        out += """<style>
:root { --fg: #24292f; --bg: #ffffff; --muted-bg: #f6f8fa; --border: #d0d7de; --head-bg: #eaeef2; --link: #0969da; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #e6edf3; --bg: #0d1117; --muted-bg: #161b22; --border: #30363d; --head-bg: #21262d; --link: #4493f8; }
}
body { font-family: system-ui, sans-serif; margin: 40px auto; max-width: 900px; padding: 0 12px; line-height: 1.6; color: var(--fg); background: var(--bg); }
a { color: var(--link); }
table { border-collapse: collapse; width: 100%; margin: 20px 0; }
th, td { border: 1px solid var(--border); padding: 8px; text-align: left; }
th { background-color: var(--head-bg); }
pre { background: var(--muted-bg); padding: 15px; overflow-x: auto; border: 1px solid var(--border); }
code { background: var(--muted-bg); }
hr { margin: 40px 0; border: 0; border-top: 2px solid var(--border); }
.filter-bar { padding: 15px; background: var(--muted-bg); border: 1px solid var(--border); margin-bottom: 20px; border-radius: 4px; display: flex; flex-wrap: wrap; gap: 10px; }
.filter-bar input, .filter-bar select { padding: 8px; border: 1px solid var(--border); border-radius: 4px; background: var(--bg); color: var(--fg); }
"""
        out += "</style>\n</head>\n<body>\n"

        # Inject Filter Bar
        out += """
<div class="filter-bar">
  <input type="text" id="searchTitle" placeholder="Search by title..." aria-label="Search by title">
  <select id="filterSeverity" aria-label="Filter by severity">
    <option value="All">All Severities</option>
    <option value="Critical">Critical</option>
    <option value="High">High</option>
    <option value="Medium">Medium</option>
    <option value="Low">Low</option>
    <option value="Info">Info</option>
  </select>
</div>
<script>
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
        """
        errors = errors or []

        def produce(staging: Path) -> list[str]:
            data: dict[str, Any] = {
                "schema_version": JSON_SCHEMA_VERSION,
                "complete": not errors,
                "errors": errors,
                "findings": [f.model_dump() for f in findings],
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
                                 "References", "Other Reports", "Import Status"])
                for finding in findings:
                    hosts_str = ", ".join(
                        f"{h.ip} ({h.hostname})" if h.hostname else h.ip for h in finding.hosts
                    )
                    cvss_str = str(finding.cvss_score) if finding.cvss_score is not None else ""
                    evidence_str = "\n---\n".join(
                        f"{e.type}{f' [{e.source}]' if e.source else ''}:\n{e.data}"
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
                    ]])
            return ["report.csv"]

        return self._publish("csv", produce, replace)
