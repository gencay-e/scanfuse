import os
import tempfile
from collections import Counter
from pathlib import Path

from fpdf import FPDF

from scanfuse.engine import OutputExistsError
from scanfuse.models import Finding


def _exists_message(target: Path) -> str:
    return (
        f"1 file(s) already exist in {target.parent} ({target.name}). "
        "Use --replace to overwrite them, or choose another output directory."
    )


def export_pdf(
    output_dir: Path,
    findings: list[Finding],
    errors: list[dict[str, str]] | None = None,
    replace: bool = False,
    resolved: list[Finding] | None = None,
) -> list[str]:
    target = output_dir / "report.pdf"
    if target.exists() and not replace:
        raise OutputExistsError(_exists_message(target))
    font_path = _unicode_font_path()
    if font_path:
        font_name = "ReportUnicode"
        is_unicode = True
    else:
        font_name = "helvetica"
        is_unicode = False

    class ReportPDF(FPDF):
        def footer(self) -> None:
            self.set_y(-12)
            self.set_font(font_name, size=8)
            self.cell(0, 8, s("Page ") + str(self.page_no()) + "/{nb}", align="C")

    pdf = ReportPDF()
    if font_path:
        pdf.add_font("ReportUnicode", fname=str(font_path))
    pdf.alias_nb_pages()

    def s(val: object) -> str:
        return _safe(val, is_unicode=is_unicode)

    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font(font_name, size=24)
    pdf.cell(0, 20, "scanfuse Security Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font(font_name, size=12)
    status = "incomplete" if errors else "complete"
    pdf.cell(
        0,
        10,
        f"Management Summary: {len(findings)} findings ({status})",
        new_x="LMARGIN",
        new_y="NEXT",
    )
    counts = Counter(f.severity for f in findings)
    pdf.set_font(font_name, size=10)
    pdf.cell(35, 7, s("Severity"), border=1)
    pdf.cell(35, 7, s("Count"), border=1, new_x="LMARGIN", new_y="NEXT")
    for severity in ("Critical", "High", "Medium", "Low", "Info"):
        pdf.cell(35, 7, s(severity), border=1)
        pdf.cell(35, 7, str(counts.get(severity, 0)), border=1, new_x="LMARGIN", new_y="NEXT")
    if errors:
        pdf.ln(3)
        pdf.set_font(font_name, size=12)
        pdf.cell(0, 8, s(f"Import errors ({len(errors)})"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(font_name, size=9)
        for error in errors:
            for key, value in error.items():
                pdf.multi_cell(0, 5, s(f"{key}: {value}"), new_x="LMARGIN", new_y="NEXT")
    if resolved:
        pdf.ln(3)
        pdf.set_font(font_name, size=11)
        pdf.multi_cell(0, 7, s(f"Resolved findings: {len(resolved)}"), new_x="LMARGIN", new_y="NEXT")
        for item in resolved:
            pdf.multi_cell(0, 5, s(f"- {item.title} ({item.severity})"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_auto_page_break(auto=True, margin=15)
    for finding in findings:
        pdf.add_page()
        pdf.set_font(font_name, size=16)
        pdf.multi_cell(0, 10, s(finding.title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(font_name, size=11)
        pdf.cell(
            0,
            8,
            s(f"{finding.severity} | {finding.source_tool}" + (f" | Status: {finding.status}" if finding.status else "")),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_font(font_name, size=10)
        pdf.multi_cell(
            0, 6, s(finding.description), new_x="LMARGIN", new_y="NEXT"
        )
        if finding.hosts:
            pdf.multi_cell(
                0,
                6,
                s("Hosts: " + ", ".join(f"{host.ip}" + (f" ({host.hostname})" if host.hostname else "") for host in finding.hosts)),
                new_x="LMARGIN",
                new_y="NEXT",
            )
        places = finding.affected()
        if places:
            pdf.multi_cell(
                0, 6, s("Affected:\n" + "\n".join(places)), new_x="LMARGIN", new_y="NEXT"
            )
        if finding.remediation:
            pdf.multi_cell(
                0,
                6,
                s("Remediation: " + finding.remediation),
                new_x="LMARGIN",
                new_y="NEXT",
            )
        if finding.cvss_score is not None:
            pdf.multi_cell(
                0,
                6,
                s(f"CVSS: {finding.cvss_score}"),
                new_x="LMARGIN",
                new_y="NEXT",
            )
        if finding.port:
            pdf.multi_cell(
                0,
                6,
                s("Port: " + finding.port),
                new_x="LMARGIN",
                new_y="NEXT",
            )
        if finding.identifiers:
            pdf.multi_cell(
                0,
                6,
                s("Identifiers: " + ", ".join(finding.identifiers)),
                new_x="LMARGIN",
                new_y="NEXT",
            )
        if finding.references:
            pdf.multi_cell(
                0,
                6,
                s("References: " + ", ".join(finding.references)),
                new_x="LMARGIN",
                new_y="NEXT",
            )
        if finding.tags:
            pdf.multi_cell(0, 6, s("Tags: " + ", ".join(finding.tags)), new_x="LMARGIN", new_y="NEXT")
        for source in finding.sources:
            pdf.multi_cell(0, 6, s(f"Reported by: {source.source_tool} | {source.title} | {source.severity}"), new_x="LMARGIN", new_y="NEXT")
        for evidence in finding.evidence:
            max_chars = 12000
            data = evidence.data
            if len(data) > max_chars:
                data = data[:max_chars] + "\n[Evidence shortened; see full text in Markdown/JSON report.]"
            pdf.multi_cell(
                0,
                6,
                s(f"Evidence ({evidence.type}): {data}"),
                new_x="LMARGIN",
                new_y="NEXT",
            )
    output_dir.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=".report-", suffix=".pdf", dir=output_dir
    )
    os.close(fd)
    try:
        pdf.output(temporary)
        if target.exists() and not replace:
            raise OutputExistsError(_exists_message(target))
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return ["report.pdf"]


def _safe(value: object, is_unicode: bool = True) -> str:
    text = str(value or "")
    if not is_unicode:
        return text.encode("latin-1", "replace").decode("latin-1")
    return text


def _unicode_font_path() -> Path | None:
    candidates = (
        Path("C:/Windows/Fonts/arial.ttf"),
        Path("C:/Windows/Fonts/segoeui.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/dejavu/DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/freefont/FreeSans.ttf"),
        Path("/usr/share/fonts/liberation-sans/LiberationSans-Regular.ttf"),
        Path("/Library/Fonts/Arial.ttf"),
        Path("/System/Library/Fonts/Supplemental/Arial.ttf"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None
