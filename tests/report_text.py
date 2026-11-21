"""Print an HTML report as lines the tests can grep: '# ' and '## ' headings, '| a | b |' table rows, and
one line per paragraph, list item or card. Scripts and styles are left out. Test-only; standard library only.

    python3 tests/report_text.py report.html > report.txt
"""

import sys
from html.parser import HTMLParser

BLOCKS = {"p", "div", "section", "header", "footer", "li", "ul", "ol", "table", "figure", "figcaption", "h1", "h2", "h3"}
HEADINGS = {"h1": "# ", "h2": "## ", "h3": "### "}


class Flatten(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.lines: list[str] = []
        self.line: list[str] = []
        self.cells: list[str] | None = None   # inside a <tr>
        self.cell: list[str] | None = None    # inside a <td> or <th>
        self.skip = 0                         # inside <script>, <style> or <title>

    def flush(self) -> None:
        text = " ".join("".join(self.line).split())
        if text:
            self.lines.append(text)
        self.line = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "title"):
            self.skip += 1
        elif tag == "tr":
            self.flush()
            self.cells = []
        elif tag in ("td", "th") and self.cells is not None:
            self.cell = []
        elif self.cell is not None:
            self.cell.append(" ")
        elif tag in BLOCKS:
            self.flush()
            self.line.append(HEADINGS.get(tag, ""))
        else:  # an inline piece (a span, a link, svg text) is a word of its own
            self.line.append(" ")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "title"):
            self.skip -= 1
        elif tag in ("td", "th") and self.cell is not None:
            self.cells.append(" ".join("".join(self.cell).split()))
            self.cell = None
        elif tag == "tr" and self.cells is not None:
            self.lines.append("| " + " | ".join(self.cells) + " |")
            self.cells = None
        elif self.cell is None and tag in BLOCKS:
            self.flush()

    def handle_data(self, data):
        if self.skip:
            return
        (self.cell if self.cell is not None else self.line).append(data)


def main() -> None:
    parser = Flatten()
    with open(sys.argv[1], encoding="utf-8") as fh:
        parser.feed(fh.read())
    parser.flush()
    print("\n".join(parser.lines))


if __name__ == "__main__":
    main()
