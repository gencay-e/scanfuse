"""Render untrusted report Markdown as restricted HTML fragments."""

import markdown
import nh3

REPORT_TAGS = {
    "a", "b", "blockquote", "br", "code", "del", "div", "em",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "li", "ol",
    "p", "pre", "s", "strong", "table", "tbody", "td", "th", "thead", "tr", "ul",
}


def _rewrite_internal_md_link(tag: str, attribute: str, value: str) -> str:
    if tag == "a" and attribute == "href" and value.endswith(".md"):
        if ":" not in value and not value.startswith(("//", "/", "#")):
            return "#" + value[:-3]
    return value


def render_report_fragment(content: str) -> str:
    rendered = markdown.markdown(content, extensions=["tables", "fenced_code"])
    return nh3.clean(
        rendered,
        tags=REPORT_TAGS,
        attributes={"a": {"href", "title"}},
        attribute_filter=_rewrite_internal_md_link,
        url_schemes={"http", "https", "mailto"},
    )
