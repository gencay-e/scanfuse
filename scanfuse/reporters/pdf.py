import os
import tempfile
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
) -> list[str]:
    target = output_dir / "report.pdf"
    if target.exists() and not replace:
        raise OutputExistsError(_exists_message(target))
    pdf = FPDF()
    font_path = _unicode_font_path()
    if font_path:
        pdf.add_font("ReportUnicode", fname=str(font_path))
        font_name = "ReportUnicode"
        is_unicode = True
    else:
        font_name = "helvetica"
        is_unicode = False

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
    for finding in findings:
        pdf.add_page()
        pdf.set_font(font_name, size=16)
        pdf.multi_cell(0, 10, s(finding.title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font(font_name, size=11)
        pdf.cell(
            0,
            8,
            s(f"{finding.severity} | {finding.source_tool}"),
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
                s("Hosts: " + ", ".join(host.ip for host in finding.hosts)),
                new_x="LMARGIN",
                new_y="NEXT",
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
        for evidence in finding.evidence:
            pdf.multi_cell(
                0,
                6,
                s(f"Evidence ({evidence.type}): {evidence.data}"),
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
