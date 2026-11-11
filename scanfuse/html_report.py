"""Render untrusted report Markdown as restricted HTML fragments."""

import re

import markdown
import nh3

REPORT_TAGS = {
    "a", "b", "blockquote", "br", "code", "del", "div", "em",
    "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "li", "ol",
    "p", "pre", "s", "strong", "table", "tbody", "td", "th", "thead", "tr", "ul",
}


def _rewrite_internal_md_link(match: re.Match) -> str:
    target = match.group(1)
    if "://" in target or target.startswith(("//", "/", "mailto:", "javascript:")):
        return match.group(0)
    return f"](#{target})"


def render_report_fragment(content: str) -> str:
    content = re.sub(r'\]\(([^)]+)\.md\)', _rewrite_internal_md_link, content)
    rendered = markdown.markdown(content, extensions=["tables", "fenced_code"])
    return nh3.clean(
        rendered,
        tags=REPORT_TAGS,
        attributes={"a": {"href", "title"}},
        url_schemes={"http", "https", "mailto"},
    )
