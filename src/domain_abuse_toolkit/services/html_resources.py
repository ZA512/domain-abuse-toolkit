from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from domain_abuse_toolkit.services.evidence import PendingArtifact

_LINK_TAG = re.compile(r"<link\b[^>]*>", flags=re.IGNORECASE | re.DOTALL)
_STYLE_END = re.compile(r"</style", flags=re.IGNORECASE)


class _ResourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.base_href: str | None = None
        self.stylesheet_hrefs: list[str] = []
        self.stylesheet_media: list[str | None] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        values = {name.casefold(): value for name, value in attrs}
        if tag.casefold() == "base" and self.base_href is None:
            self.base_href = values.get("href")
            return
        if tag.casefold() != "link":
            return
        relations = (values.get("rel") or "").casefold().split()
        href = values.get("href")
        if (
            "stylesheet" in relations
            and "alternate" not in relations
            and "disabled" not in values
            and href
        ):
            self.stylesheet_hrefs.append(href)
            self.stylesheet_media.append(values.get("media"))


def extract_stylesheet_urls(
    source: bytes, document_url: str, *, max_stylesheets: int = 8
) -> list[str]:
    parser = _ResourceParser()
    parser.feed(source.decode("utf-8", errors="replace"))
    base_url = urljoin(document_url, parser.base_href) if parser.base_href else document_url
    urls: list[str] = []
    for href in parser.stylesheet_hrefs:
        candidate = urljoin(base_url, href)
        parsed = urlsplit(candidate)
        if (
            parsed.scheme.casefold() not in {"http", "https"}
            or not parsed.hostname
            or len(candidate) > 4096
            or candidate in urls
        ):
            continue
        urls.append(candidate)
        if len(urls) >= max_stylesheets:
            break
    return urls


def inline_collected_stylesheets(
    source: bytes,
    document_url: str,
    stylesheets: list[PendingArtifact],
) -> tuple[bytes, int]:
    """Replace collected stylesheet links while leaving uncollected links inert."""
    text = source.decode("utf-8", errors="replace")
    mapping = {
        str(artifact.metadata.get("stylesheet_url")): artifact
        for artifact in stylesheets
        if artifact.media_type == "text/css"
        and artifact.metadata.get("stylesheet_url")
        and not artifact.metadata.get("truncated")
    }
    document_parser = _ResourceParser()
    document_parser.feed(text)
    base_url = (
        urljoin(document_url, document_parser.base_href)
        if document_parser.base_href
        else document_url
    )
    inlined = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal inlined
        parser = _ResourceParser()
        parser.feed(match.group(0))
        if not parser.stylesheet_hrefs:
            return match.group(0)
        stylesheet_url = urljoin(base_url, parser.stylesheet_hrefs[0])
        artifact = mapping.get(stylesheet_url)
        if artifact is None:
            return match.group(0)
        css = artifact.content.decode("utf-8", errors="replace")
        css = _STYLE_END.sub(r"<\\/style", css)
        media = parser.stylesheet_media[0]
        media_attribute = (
            f' media="{html.escape(media, quote=True)}"' if media else ""
        )
        inlined += 1
        return (
            f'<style data-dat-stylesheet="{html.escape(stylesheet_url, quote=True)}"'
            f"{media_attribute}>"
            f"{css}</style>"
        )

    rendered = _LINK_TAG.sub(replace, text)
    return rendered.encode("utf-8"), inlined
