from domain_abuse_toolkit.services.evidence import PendingArtifact
from domain_abuse_toolkit.services.html_resources import (
    extract_stylesheet_urls,
    inline_collected_stylesheets,
)


def test_stylesheet_extraction_honors_base_deduplicates_and_bounds() -> None:
    source = b"""
    <base href="https://cdn.example.net/assets/">
    <link rel="stylesheet" href="app.css">
    <link href="app.css" rel="stylesheet alternate">
    <link rel="stylesheet" href="data:text/css,body{}">
    <link rel="icon" href="icon.css">
    """

    assert extract_stylesheet_urls(source, "https://example.net/page", max_stylesheets=2) == [
        "https://cdn.example.net/assets/app.css"
    ]


def test_stylesheet_inlining_escapes_style_end_markup() -> None:
    source = (
        b'<link rel="stylesheet" href="/app.css" media="screen and (min-width: 600px)">'
        b"<main>Evidence</main>"
    )
    stylesheet = PendingArtifact(
        relative_path="styles/00.css",
        content=b"body { color: red } </style><script>ignored</script>",
        media_type="text/css",
        source="test",
        metadata={
            "stylesheet_url": "https://example.net/app.css",
            "truncated": False,
        },
    )

    rendered, count = inline_collected_stylesheets(
        source, "https://example.net/page", [stylesheet]
    )

    assert count == 1
    assert (
        b'<style data-dat-stylesheet="https://example.net/app.css" '
        b'media="screen and (min-width: 600px)">' in rendered
    )
    assert b"</style><script>" not in rendered
    assert b"<\\/style><script>ignored</script>" in rendered
