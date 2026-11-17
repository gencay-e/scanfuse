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
from scanfuse.baseline import compare_baseline
from scanfuse.config import apply_overrides, load_config, validate_config
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
    """Compatibility wrapper around the shared strict configuration validator."""
    try:
        config = validate_config(config_data)
    except ValueError as exc:
        return [], str(exc)
    return list(config.get("ignore_titles", [])), None


@app.command()
def parse(
    file_paths: list[str] = typer.Argument(None, help="Paths to the scan files (or '-' for stdin)"),
    format: InputFormat = typer.Option(
        InputFormat.auto, "--format", "-f", case_sensitive=False, help="Input format. auto detects all 11 supported scanner formats.",
    ),
    output: str = typer.Option("report", "--output", "-o", help="Output directory"),
    config_file: Path | None = typer.Option(None, "--config", "-c", exists=True, file_okay=True, dir_okay=False, readable=True, help="Configuration YAML file (default: .scanfuse.yaml)"),
    baseline: Path | None = typer.Option(None, "--baseline", file_okay=True, dir_okay=False, help="Compare with a complete schema_version 2 report"),
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

    config_path = config_file or Path(".scanfuse.yaml")
    config: dict = {}
    config_error: str | None = None
    if config_path.exists() or config_file is not None:
        try:
            config = load_config(config_path)
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            config_error = str(exc)
    errors: list[dict[str, str]] = []
    if config_error:
        message = f"{config_path}: {config_error}"
        console.print(f"[red]Error: {escape(message)}[/red]")
        errors.append({"file": str(config_path), "message": config_error})

    out_path = Path(output)
    if out_path.exists() and not out_path.is_dir():
        console.print(f"[red]Error: output path is a file, not a directory: {escape(output)}[/red]")
        raise typer.Exit(code=EXIT_USAGE)

    engine = ScanfuseEngine(output_dir=output, template_dir=str(template_dir) if template_dir else None)

    all_findings = []

    for file_path in file_paths:
        is_temp = False
        target_path = file_path

        if file_path == "-":
            fd, target_path = tempfile.mkstemp(suffix=".tmp")
            is_temp = True
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(sys.stdin.buffer.read())
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                os.remove(target_path)
                raise

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

    if all_findings or baseline is not None or config_error is not None:
        ignore_rules: list[str] = list(config.get("ignore_titles", []))
        if config_path.exists() and config_error is None:
            console.print(f"[bold blue]scanfuse[/bold blue] > Loaded {len(ignore_rules)} ignore rules from {escape(str(config_path))}")

        # The host filter runs before merging, so that severity, CVSS and sources of a merged
        # finding come only from the selected hosts.
        if host_filter:
            all_findings = engine.filter_by_host(all_findings, host_filter)

        # Deduplicate next so that multi-tool evidence and consolidated max severity are preserved
        from scanfuse.utils import deduplicate_findings
        original_count = len(all_findings)
        all_findings = deduplicate_findings(all_findings)
        if len(all_findings) < original_count:
            console.print(f"[bold yellow]scanfuse[/bold yellow] > Merged {original_count} findings into {len(all_findings)}.")

        if config_error is None:
            all_findings = apply_overrides(all_findings, config)


        if baseline is not None:
            try:
                resolved = compare_baseline(all_findings, baseline, complete=not errors)
                if host_filter:
                    resolved = engine.filter_by_host(resolved, host_filter)
                if config_error is None:
                    resolved = apply_overrides(resolved, config)
                engine.resolved = engine.filter_findings(
                    resolved, min_severity=min_severity_name, ignore_rules=ignore_rules,
                )
            except (OSError, ValueError) as exc:
                message = f"{baseline}: {exc}"
                console.print(f"[red]Error: {escape(message)}[/red]")
                errors.append({"file": str(baseline), "message": str(exc)})

        all_findings = engine.filter_findings(all_findings, min_severity=min_severity_name, ignore_rules=ignore_rules)
        if not all_findings:
            console.print("[yellow]No findings left after applying filters.[/yellow]")
            if baseline is None and not errors:
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

    if not all_findings and not errors and baseline is None:
        console.print("[yellow]The input contains no findings. Nothing was exported.[/yellow]")

    if errors:
        console.print(f"[yellow]The report is incomplete: {len(errors)} problem(s), see above.[/yellow]")
        raise typer.Exit(code=EXIT_INCOMPLETE)

if __name__ == "__main__":
    app()
