"""Render untrusted report Markdown as restricted HTML fragments."""

import re

import markdown
import nh3

REPORT_TAGS = {
    "a", "b", "blockquote", "br", "code", "del", "div", "em",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "li", "ol",
    "p", "pre", "s", "strong", "table", "tbody", "td", "th", "thead", "tr", "ul",
}
_FLAT_MD_LINK = re.compile(r"^([a-z0-9-]+)\.md(?:#.*)?$")


def render_report_fragment(content: str, finding_slugs: set[str] | None = None) -> str:
    def _rewrite_internal_md_link(tag: str, attribute: str, value: str) -> str:
        if tag == "a" and attribute == "href":
            match = _FLAT_MD_LINK.match(value)
            if match:
                slug = match.group(1)
                if finding_slugs is None or slug in finding_slugs:
                    return f"#{slug}"
        return value

    rendered = markdown.markdown(content, extensions=["tables", "fenced_code"])
    return nh3.clean(
        rendered,
        tags=REPORT_TAGS,
        attributes={"a": {"href", "title"}},
        attribute_filter=_rewrite_internal_md_link,
        url_schemes={"http", "https", "mailto"},
    )
