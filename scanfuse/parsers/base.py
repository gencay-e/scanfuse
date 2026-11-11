import re
from abc import ABC, abstractmethod
from html.parser import HTMLParser

from scanfuse.models import Finding


class PartialImportError(ValueError):
    """Input contains usable findings and errors that must be reported."""

    def __init__(self, message: str, findings: list[Finding]) -> None:
        super().__init__(message)
        self.findings = findings


_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_TEXT = re.compile(r"\bCWE[-\s#:]*(\d{1,5})\b", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s<>\"'\\]+", re.IGNORECASE)


class _TextExtractor(HTMLParser):
    """Turns the small HTML subset that scanners put into text fields into plain text."""

    _BLOCK = {"p", "div", "ul", "ol", "table", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "pre", "blockquote"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "br":
            self.parts.append("\n")
        elif tag == "li":
            self.parts.append("\n- ")
        elif tag in ("td", "th"):
            self.parts.append(" ")
        elif tag in self._BLOCK:
            self.parts.append("\n\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag in ("td", "th"):
            self.parts.append(" ")
        elif tag in self._BLOCK or tag == "li":
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(value: object) -> str:
    """Plain text from a field that may contain HTML tags or HTML entities.

    Line breaks and list items are kept. Scripts are dropped. Text without markup is returned
    with entities decoded and surrounding space removed.
    """
    text = "" if value is None else str(value)
    if "<" not in text and "&" not in text:
        return text.strip()
    parser = _TextExtractor()
    parser.feed(text)
    parser.close()
    result = "".join(parser.parts).replace("\xa0", " ")
    result = re.sub(r"[ \t]+\n", "\n", result)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip()


def extract_urls(*values: object) -> list[str]:
    """http(s) URLs found in strings, HTML or lists of them, without duplicates."""
    found: list[str] = []
    items: list[object] = []
    for value in values:
        items.extend(value if isinstance(value, (list, tuple)) else [value])
    for item in items:
        text = str(item or "")
        for match in _URL.findall(text):
            url = match.rstrip(".,;:)]}")
            if url and url not in found:
                found.append(url)
    return found


def cwe_ids_from_text(*values: object) -> list[str]:
    """CWE ids named in free text, as 'CWE-79'."""
    found: list[str] = []
    for value in values:
        for number in _CWE_TEXT.findall(str(value or "")):
            cwe = f"CWE-{int(number)}"
            if int(number) > 0 and cwe not in found:
                found.append(cwe)
    return found


def clean_ids(*values: object) -> list[str]:
    """Return unique, non-empty identifier strings in the order given."""
    result: list[str] = []
    for value in values:
        if isinstance(value, (list, tuple)):
            items = list(value)
        else:
            items = [value]
        for item in items:
            if item is None:
                continue
            text = str(item).strip()
            if text and text not in result:
                result.append(text)
    return result


def cve_ids(value: object) -> list[str]:
    """Extract CVE ids from a string or list of strings."""
    found: list[str] = []
    items = value if isinstance(value, (list, tuple)) else [value]
    for item in items:
        for match in _CVE.findall(str(item or "")):
            cve = match.upper()
            if cve not in found:
                found.append(cve)
    return found


def cwe_id(value: object) -> str | None:
    """Return 'CWE-<n>' for a numeric or 'CWE-n' value, otherwise None."""
    text = str(value or "").strip().upper().removeprefix("CWE-")
    return f"CWE-{text}" if text.isdigit() and int(text) > 0 else None


class BaseParser(ABC):
    """
    Abstract base class for all scanfuse parsers.
    """

    @abstractmethod
    def parse(self, file_path: str) -> list[Finding]:
        """
        Parse the given file and return a list of Finding objects.
        Must handle malformed files gracefully and raise ValueError if the format is fundamentally wrong.
        """
        pass
