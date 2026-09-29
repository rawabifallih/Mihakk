"""Strict reader for a rendered HTML report: is there any executable context?

The report renders text the target influenced. The engine's indicator reason embeds
bytes taken from the response body, the request summary carries the mutated payload,
and the response summary carries transport error text. So the question this answers
is not "does the page contain a suspicious string" but "could a browser act on
anything in it".

That distinction decides how the check works. Searching the raw markup for
`javascript:` or `onerror=` is the wrong test twice over: it misses an encoding the
search did not anticipate, and it fails on a page that is doing exactly the right
thing, since an escaped payload shown as visible text legitimately contains those
characters. The report is required to keep the payload readable. So the document is
parsed, and the verdict comes from the elements, attributes and URL schemes a
browser would actually honour.

    exit 0  no executable context, and every required protection present
    exit 1  something a browser could act on
    exit 2  the page could not be parsed, so nothing was established
"""

from __future__ import annotations

import html.parser
import sys

EXIT_SAFE = 0
EXIT_UNSAFE = 1
EXIT_UNVERIFIED = 2

# Elements that execute, navigate, submit, or pull in something else.
EXECUTABLE_ELEMENTS = {
    "script", "iframe", "object", "embed", "applet", "frame", "frameset",
    "base", "form", "input", "button", "textarea", "select", "link", "audio",
    "video", "source", "track", "portal",
}

URL_ATTRIBUTES = {
    "href", "src", "action", "formaction", "xlink:href", "srcset", "poster",
    "background", "data", "codebase", "cite", "longdesc", "usemap", "profile",
    "manifest", "ping",
}

DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:", "file:", "blob:")
EXTERNAL_PREFIXES = ("http://", "https://", "//", "ftp:")


class Page(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[str] = []
        self.event_attributes: list[str] = []
        self.style_attributes: list[str] = []
        self.urls: list[tuple[str, str, str]] = []
        self.meta_refresh = False
        self.csp: str | None = None
        self.text_parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.elements.append(tag)
        attr_map = {}
        for name, value in attrs:
            lowered = name.lower()
            attr_map[lowered] = value or ""
            if lowered.startswith("on"):
                self.event_attributes.append(f"<{tag} {lowered}>")
            if lowered == "style":
                self.style_attributes.append(f"<{tag}>")
            if lowered in URL_ATTRIBUTES:
                self.urls.append((tag, lowered, value or ""))
        if tag == "meta":
            if attr_map.get("http-equiv", "").lower() == "refresh":
                self.meta_refresh = True
            if attr_map.get("http-equiv", "").lower() == "content-security-policy":
                self.csp = attr_map.get("content", "")

    def handle_data(self, data):
        if data.strip():
            self.text_parts.append(data)

    @property
    def text(self) -> str:
        return "\n".join(self.text_parts)


def check(markup: str) -> tuple[int, list[str]]:
    """Return (exit code, messages). Messages are prefixed PASS/FAIL/UNVERIFIED."""
    page = Page()
    try:
        page.feed(markup)
        page.close()
    except Exception as exc:  # a parser error means nothing was established
        return EXIT_UNVERIFIED, [f"UNVERIFIED\tthe page could not be parsed ({exc})"]

    if not page.elements:
        return EXIT_UNVERIFIED, ["UNVERIFIED\tthe page has no elements; it was probably not HTML"]

    messages: list[str] = []
    problems: list[str] = []

    executable = sorted({e for e in page.elements if e in EXECUTABLE_ELEMENTS})
    if executable:
        problems.append(f"FAIL\texecutable element(s) present: {', '.join(executable)}")
    else:
        messages.append("PASS\tno executable element in the document")

    if page.event_attributes:
        problems.append("FAIL\tevent-handler attribute(s): "
                        + ", ".join(sorted(set(page.event_attributes))))
    else:
        messages.append("PASS\tno event-handler attribute")

    if page.style_attributes:
        problems.append("FAIL\tstyle attribute(s): "
                        + ", ".join(sorted(set(page.style_attributes))))
    else:
        messages.append("PASS\tno inline style attribute")

    if page.meta_refresh:
        problems.append("FAIL\ta meta refresh can navigate the page")
    else:
        messages.append("PASS\tno meta refresh")

    bad_urls: list[str] = []
    external: list[str] = []
    for tag, attr, value in page.urls:
        collapsed = value.strip().lower().replace("\t", "").replace("\n", "").replace("\r", "")
        if collapsed.startswith(DANGEROUS_SCHEMES):
            bad_urls.append(f"<{tag} {attr}={value[:60]!r}>")
        elif collapsed.startswith(EXTERNAL_PREFIXES):
            external.append(f"<{tag} {attr}={value[:60]!r}>")
    if bad_urls:
        problems.append("FAIL\tURL(s) with an executable scheme: " + ", ".join(bad_urls))
    else:
        messages.append("PASS\tno URL with an executable scheme")
    if external:
        problems.append("FAIL\texternal resource reference(s): " + ", ".join(external))
    else:
        messages.append("PASS\tnothing is loaded from anywhere")

    if not page.csp:
        problems.append("FAIL\tno Content-Security-Policy meta fallback for a saved copy")
    else:
        for directive in ("default-src 'none'", "base-uri 'none'", "form-action 'none'"):
            if directive not in page.csp:
                problems.append(f"FAIL\tthe meta policy is missing {directive}")
                break
        else:
            messages.append("PASS\ta Content-Security-Policy meta fallback is present")

    if problems:
        return EXIT_UNSAFE, messages + problems
    return EXIT_SAFE, messages


def main() -> int:
    if len(sys.argv) != 2:
        print("UNVERIFIED\tusage: check_report_html.py <file>")
        return EXIT_UNVERIFIED
    try:
        with open(sys.argv[1], "r", encoding="utf-8") as handle:
            markup = handle.read()
    except OSError as exc:
        print(f"UNVERIFIED\tcould not read {sys.argv[1]}: {exc}")
        return EXIT_UNVERIFIED
    if not markup.strip():
        print("UNVERIFIED\tthe file is empty")
        return EXIT_UNVERIFIED

    code, messages = check(markup)
    for message in messages:
        print(message)
    return code


if __name__ == "__main__":
    sys.exit(main())
