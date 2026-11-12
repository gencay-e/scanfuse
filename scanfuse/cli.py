import os
import sys
import tempfile
from enum import StrEnum
from pathlib import Path

import jinja2
import typer
from rich.console import Console
from rich.markup import escape

from scanfuse import __version__
from scanfuse.engine import OutputExistsError, ScanfuseEngine
from scanfuse.parsers.base import PartialImportError

app = typer.Typer(
    name="scanfuse",
    help="Merge pentest scanner findings into one report: Markdown/HTML, JSON, CSV, SARIF or PDF. Runs offline.",
    add_completion=False,
)
console = Console()

class InputFormat(StrEnum):
    auto = "auto"
    nmap = "nmap"
    nuclei = "nuclei"
    zap = "zap"
    burp = "burp"
    nessus = "nessus"
    trivy = "trivy"
    sarif = "sarif"
    semgrep = "semgrep"
    grype = "grype"
    nikto = "nikto"
    testssl = "testssl"


class OutputFormat(StrEnum):
    markdown = "markdown"
    json = "json"
    csv = "csv"
    sarif = "sarif"
    pdf = "pdf"


class Severity(StrEnum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    info = "Info"


# Exit codes: 0 = ok, 1 = the run was incomplete or failed, 2 = invalid usage or the output
# directory already contains files (use --replace).
EXIT_INCOMPLETE = 1
EXIT_USAGE = 2


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"scanfuse {__version__}")
        raise typer.Exit()


def parse_config(config_data: object) -> tuple[list[str], str | None]:
    """Validate the content of .scanfuse.yaml.

    Returns the ignore rules and an error message. If the message is set, the
    rules are empty. A single string for ignore_titles is accepted as a list
    with one entry.
    """
    if config_data is None:
        return [], None
    if not isinstance(config_data, dict):
        return [], "the file must contain a mapping (key: value)."
    value = config_data.get("ignore_titles")
    if value is None:
        return [], None
    if isinstance(value, str):
        cleaned = value.strip()
        return ([cleaned] if cleaned else []), None
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        cleaned_list = [item.strip() for item in value if item.strip()]
        return cleaned_list, None
    return [], "ignore_titles must be a list of strings."


def _load_ignore_rules(config_path: Path) -> tuple[list[str], str | None]:
    """Read .scanfuse.yaml. Returns (rules, error). On any error the rules are empty."""
    import yaml
    try:
        with open(config_path, encoding="utf-8") as cf:
            config_data = yaml.safe_load(cf)
    except yaml.YAMLError as e:
        problem = getattr(e, "problem", None) or str(e).splitlines()[0]
        mark = getattr(e, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        return [], f"invalid YAML{where}: {problem}"
    except (OSError, UnicodeDecodeError) as e:
        return [], f"cannot read the file: {e}"
    return parse_config(config_data)


@app.command()
def parse(
    file_paths: list[str] = typer.Argument(None, help="Paths to the scan files (or '-' for stdin)"),
    format: InputFormat = typer.Option(
        InputFormat.auto, "--format", "-f", case_sensitive=False, help="Input format. auto detects nmap, nuclei, zap, burp, nessus and trivy. sarif, semgrep, grype, nikto and testssl are experimental and must be set explicitly.",
    ),
    output: str = typer.Option("report", "--output", "-o", help="Output directory"),
    format_out: OutputFormat = typer.Option(
        OutputFormat.markdown, "--format-out", case_sensitive=False,
        help="Output format. markdown also writes index.md and report.html.",
    ),
    min_severity: Severity | None = typer.Option(
        None, "--min-severity", "-s", case_sensitive=False, help="Minimum severity to include",
    ),
    host_filter: str = typer.Option(
        None, "--host",
        help="Only include findings affecting this host/IP (exact match, ignoring case; * and ? are wildcards)",
    ),
    template_dir: Path = typer.Option(
        None, "--template-dir", "-t", exists=True, file_okay=False, dir_okay=True,
        help="Custom directory containing Jinja2 templates (finding.md.j2, index.md.j2)",
    ),
    replace: bool = typer.Option(
        False, "--replace",
        help="Overwrite an existing report in the output directory. Without it, scanfuse stops if files would be overwritten.",
    ),
    csv_excel: bool = typer.Option(
        False, "--csv-excel", help="CSV with UTF-8 byte order mark and ';' separator, for Excel",
    ),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show the version and exit",
    ),
):
    """
    Parse scan files and extract findings.

    Exit codes:
    0 = complete.
    1 = incomplete or failed (an input could not be read, or .scanfuse.yaml is invalid).
    2 = invalid options, or the output files already exist.
    """
    input_format = format.value
    output_format = format_out.value
    min_severity_name = min_severity.value if min_severity else None

    if not file_paths and not sys.stdin.isatty():
        file_paths = ["-"]

    if not file_paths:
        console.print("[red]Error: No input files provided.[/red]")
        raise typer.Exit(code=EXIT_INCOMPLETE)

    out_path = Path(output)
    if out_path.exists() and not out_path.is_dir():
        console.print(f"[red]Error: output path is a file, not a directory: {escape(output)}[/red]")
        raise typer.Exit(code=EXIT_USAGE)

    engine = ScanfuseEngine(output_dir=output, template_dir=str(template_dir) if template_dir else None)

    all_findings = []
    errors: list[dict[str, str]] = []

    for file_path in file_paths:
        is_temp = False
        target_path = file_path

        if file_path == "-":
            fd, target_path = tempfile.mkstemp(suffix=".tmp")
            with open(fd, "wb") as f:
                f.write(sys.stdin.buffer.read())
            is_temp = True

        display_path = "stdin" if is_temp else target_path
        console.print(f"[bold blue]scanfuse[/bold blue] > Parsing {escape(display_path)} (Format: {input_format})")

        try:
            findings = engine.process_file(target_path, input_format)
            all_findings.extend(findings)
            console.print(f"[green]OK[/green] Found {len(findings)} findings in {escape(display_path)}.")
        except PartialImportError as e:
            all_findings.extend(e.findings)
            message = str(e).replace(target_path, display_path)
            console.print(f"[red]Error parsing {escape(display_path)}:[/red] {escape(message)}")
            errors.append({"file": display_path, "message": message})
        except Exception as e:
            message = str(e).replace(target_path, display_path)
            console.print(f"[red]Error parsing {escape(display_path)}:[/red] {escape(message)}")
            errors.append({"file": display_path, "message": message})
        finally:
            if is_temp:
                os.remove(target_path)

    if all_findings:
        ignore_rules: list[str] = []
        config_path = Path(".scanfuse.yaml")
        if config_path.exists():
            ignore_rules, config_error = _load_ignore_rules(config_path)
            if config_error:
                console.print(f"[red]Error: .scanfuse.yaml: {escape(config_error)} Ignore rules were not applied.[/red]")
                errors.append({"file": ".scanfuse.yaml",
                               "message": f"{config_error} Ignore rules were not applied."})
            else:
                console.print(f"[bold blue]scanfuse[/bold blue] > Loaded {len(ignore_rules)} ignore rules from .scanfuse.yaml")

        # Deduplicate first so that multi-tool evidence and consolidated max severity are preserved
        from scanfuse.utils import deduplicate_findings
        original_count = len(all_findings)
        all_findings = deduplicate_findings(all_findings)
        if len(all_findings) < original_count:
            console.print(f"[bold yellow]scanfuse[/bold yellow] > Merged {original_count} findings into {len(all_findings)}.")

        try:
            from scanfuse.config import apply_overrides, load_config
            if config_path.exists():
                all_findings = apply_overrides(all_findings, load_config(config_path))
        except (OSError, UnicodeDecodeError, ValueError) as e:
            console.print(f"[red]Error: .scanfuse.yaml overrides: {escape(str(e))}[/red]")
            errors.append({"file": ".scanfuse.yaml", "message": str(e)})

        all_findings = engine.filter_findings(all_findings, min_severity=min_severity_name, host_filter=host_filter, ignore_rules=ignore_rules)
        if not all_findings:
            console.print("[yellow]No findings left after applying filters.[/yellow]")
            raise typer.Exit(code=EXIT_INCOMPLETE if errors else 0)

        console.print(f"[bold blue]scanfuse[/bold blue] > Exporting {len(all_findings)} findings to {escape(output)}/")

        try:
            if output_format == "json":
                engine.export_json(all_findings, errors=errors, replace=replace)
            elif output_format == "csv":
                engine.export_csv(all_findings, errors=errors, replace=replace, excel=csv_excel)
            elif output_format == "sarif":
                engine.export_sarif(all_findings, errors=errors, replace=replace)
            elif output_format == "pdf":
                engine.export_pdf(all_findings, errors=errors, replace=replace)
            else:
                engine.export_findings(all_findings, errors=errors, replace=replace)
        except OutputExistsError as e:
            console.print(f"[red]Error: {escape(str(e))}[/red]")
            raise typer.Exit(code=EXIT_USAGE)
        except jinja2.exceptions.TemplateError as e:
            console.print(f"[red]Error: template rendering failed: {escape(str(e))}[/red]")
            raise typer.Exit(code=EXIT_INCOMPLETE)
        except OSError as e:
            console.print(f"[red]Error: could not write the report: {escape(str(e))}[/red]")
            raise typer.Exit(code=EXIT_INCOMPLETE)
        console.print("[green]OK[/green] Done.")

    if not all_findings and not errors:
        console.print("[yellow]The input contains no findings. Nothing was exported.[/yellow]")

    if errors:
        console.print(f"[yellow]The report is incomplete: {len(errors)} problem(s), see above.[/yellow]")
        raise typer.Exit(code=EXIT_INCOMPLETE)

if __name__ == "__main__":
    app()
