#!/usr/bin/env python3
"""Render docs/pilot/RBI_REQUIREMENTS_COVERAGE.md as a PDF brief.

Why this exists
---------------
The coverage matrix is the document a regulator, an auditor or a partner is
handed. It was previously exported by hand, which meant the PDF drifted
silently behind the markdown that the engineering work actually updates. A
readiness document that disagrees with its own source is worse than none,
because a reader trusts the artefact in front of them. This script makes the
PDF a build product of the markdown, so the two cannot disagree.

Layout decision
---------------
The matrix is NOT rendered as a table. Its evidence cells run to several
hundred characters -- deliberately, because each one names the code and the
tests that back a claim -- and a five-column table makes that unreadable at
any page size. Each requirement is rendered as a labelled block instead:
identifier and requirement, the instrument that demands it, the disposition
as a coloured badge, and the evidence in full. That is the shape an auditor
reads, one requirement at a time.

Provenance
----------
The cover records the git commit and branch the PDF was rendered from, and
whether the tree was dirty at the time. A brief that cannot be traced to a
revision is not evidence of anything.

Usage:  python3 tools/render_coverage_pdf.py [output.pdf]
Deps:   reportlab (pinned in the call site's environment; no network use)
"""

from __future__ import annotations

import html
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

REPO = Path(__file__).resolve().parent.parent
SOURCE = REPO / "docs" / "pilot" / "RBI_REQUIREMENTS_COVERAGE.md"
DEFAULT_OUT = REPO / "docs" / "pilot" / "RBI_REQUIREMENTS_COVERAGE.pdf"

# ── Palette ─────────────────────────────────────────────────────────────────
INK = colors.HexColor("#1a1a1a")
MUTED = colors.HexColor("#5a5a5a")
RULE = colors.HexColor("#d4d4d4")
ACCENT = colors.HexColor("#1f3a5f")

# Disposition → badge colour. Classified by what the row actually claims, so a
# partial claim ("DONE (mechanism) / INTEGRATE (placement)") is not painted as
# a clean pass.
BADGE = {
    "DONE": colors.HexColor("#1b6e3c"),
    "EXISTS": colors.HexColor("#15803d"),
    "PARTIAL": colors.HexColor("#8a6100"),
    "BUILD": colors.HexColor("#9a3412"),
    "INTEGRATE": colors.HexColor("#1f3a5f"),
    "OWNER": colors.HexColor("#5a5a5a"),
}


def classify(disposition: str) -> str:
    """The badge word for a disposition.

    It uses the source document's OWN vocabulary -- EXISTS, DONE, BUILD,
    INTEGRATE -- rather than inventing a parallel one, because the legend the
    reader has just read defines those words and a badge saying something
    else would quietly contradict it.

    PARTIAL is the single addition, and it is the honest answer for a row
    that claims both a closed and an open half ("DONE (mechanism) /
    INTEGRATE (placement)"). Painting such a row with its closed half would
    overstate it, which is exactly the failure this whole matrix exists to
    avoid. Order matters below for that reason.
    """
    d = strip_markdown(disposition).upper()
    closed = "DONE" in d or "EXISTS" in d
    open_ = "BUILD" in d or "INTEGRATE" in d or "ENTITY'S" in d
    if closed and open_:
        return "PARTIAL"
    if "BUILD" in d:
        return "BUILD"
    if "DONE" in d:
        return "DONE"
    if "EXISTS" in d:
        return "EXISTS"
    if "INTEGRATE" in d:
        return "INTEGRATE"
    return "OWNER"


# ── Markdown → reportlab inline markup ──────────────────────────────────────
def strip_markdown(text: str) -> str:
    """Plain text, for measurement and classification."""
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return text.replace("`", "").replace("**", "").replace("*", "")


def inline(text: str) -> str:
    """Convert a markdown cell to reportlab's mini-XML.

    Escaping happens FIRST, so a literal '<' in the source can never become
    markup. Code spans are then lifted out behind placeholders before the
    emphasis passes run, because their contents are literal: the matrix
    contains paths like `/proc/<pid>/ns/*`, and an unprotected '*' inside one
    pairs with a real italic marker later in the sentence and produces
    crossed tags that reportlab rejects. Lift, transform, restore.
    """
    text = html.escape(text, quote=False)
    # Links: keep the label, drop the URL. A printed brief cannot be clicked,
    # and a bare URL mid-sentence hurts more than it helps.
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)

    spans: list[str] = []

    def stash(m: re.Match) -> str:
        spans.append(m.group(1))
        return f"\x00{len(spans) - 1}\x00"

    text = re.sub(r"`([^`]+)`", stash, text)

    # Emphasis, now safe: no code-span content remains in `text`.
    text = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"<i>\1</i>", text)

    def restore(m: re.Match) -> str:
        body = spans[int(m.group(1))]
        return f'<font face="Courier" size="8.2" color="#1f3a5f">{body}</font>'

    return re.sub(r"\x00(\d+)\x00", restore, text)


# ── Parsing ─────────────────────────────────────────────────────────────────
@dataclass
class Row:
    cells: list[str]


@dataclass
class Section:
    title: str
    headers: list[str] = field(default_factory=list)
    rows: list[Row] = field(default_factory=list)


@dataclass
class Document:
    title: str
    legend: list[str] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    closing: list[str] = field(default_factory=list)


def split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def parse(md: str) -> Document:
    doc = Document(title="RBI ecosystem requirements — coverage matrix")
    section: Section | None = None
    in_closing = False

    for raw in md.splitlines():
        line = raw.rstrip()

        if line.startswith("# "):
            doc.title = line[2:].strip()
            continue

        # The preamble blockquote is the legend. Continuation lines are
        # joined into the paragraph (or bullet) they belong to: rendering one
        # Paragraph per source line would wrap the text at the author's hard
        # line breaks rather than at the page width.
        if line.startswith(">"):
            body = line.lstrip(">").strip()
            if not body:
                doc.legend.append("")
            elif body.startswith("-") or not doc.legend or not doc.legend[-1]:
                doc.legend.append(body)
            else:
                doc.legend[-1] = f"{doc.legend[-1]} {body}"
            continue

        if line.startswith("### "):
            section = Section(title=line[4:].strip())
            doc.sections.append(section)
            in_closing = False
            continue

        if line.startswith("## "):
            heading = line[3:].strip()
            # "## 3. Reading this matrix with RBI" and similar are prose.
            if "matrix" in heading.lower() and heading.strip().startswith("1."):
                section = None
                continue
            section = Section(title=heading)
            doc.sections.append(section)
            in_closing = "reading" in heading.lower()
            continue

        if line.startswith("|"):
            cells = split_row(line)
            if all(set(c) <= {"-", ":", " "} for c in cells):
                continue  # separator
            if section is None:
                continue
            if not section.headers:
                section.headers = cells
            else:
                section.rows.append(Row(cells))
            continue

        if in_closing and line.strip():
            doc.closing.append(line.strip())

    return doc


# ── Provenance ──────────────────────────────────────────────────────────────
def git(*args: str) -> str:
    try:
        return subprocess.run(
            ["git", *args], cwd=REPO, capture_output=True, text=True, check=True
        ).stdout.strip()
    except Exception:
        return "unknown"


def provenance() -> dict[str, str]:
    """Where this render came from.

    Dirtiness is checked for the SOURCE FILE specifically, not the whole
    tree. The claim worth making is "the markdown this PDF renders is/is not
    identical to the named commit"; an unrelated edit elsewhere in the
    repository, or the untracked output file itself, would make a
    whole-tree check say "modified" and tell the reader nothing true about
    the document in their hands.
    """
    dirty = git("status", "--porcelain", "--", str(SOURCE.relative_to(REPO)))
    return {
        "commit": git("rev-parse", "--short", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "tree": "source modified since this commit" if dirty else "source matches this commit",
        "rendered": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


# ── Rendering ───────────────────────────────────────────────────────────────
def styles():
    base = getSampleStyleSheet()
    s = {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontSize=21, leading=26,
            textColor=ACCENT, spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"], fontSize=10.5, leading=15,
            textColor=MUTED, spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "h2", parent=base["Heading2"], fontSize=13.5, leading=17,
            textColor=ACCENT, spaceBefore=16, spaceAfter=8,
        ),
        "req": ParagraphStyle(
            "req", parent=base["Normal"], fontSize=10, leading=13.5,
            textColor=INK, alignment=TA_LEFT,
        ),
        "label": ParagraphStyle(
            "label", parent=base["Normal"], fontSize=7.4, leading=9,
            textColor=MUTED, spaceBefore=3,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontSize=8.6, leading=12,
            textColor=INK,
        ),
        "legend": ParagraphStyle(
            "legend", parent=base["Normal"], fontSize=9, leading=13,
            textColor=INK, spaceAfter=5,
        ),
        "note": ParagraphStyle(
            "note", parent=base["Normal"], fontSize=7.8, leading=10.5,
            textColor=MUTED,
        ),
        "legend_item": ParagraphStyle(
            "legend_item", parent=base["Normal"], fontSize=9, leading=13,
            textColor=INK, leftIndent=10, spaceAfter=4,
        ),
        "badge": ParagraphStyle(
            "badge", parent=base["Normal"], fontSize=7.6, leading=9.5,
            textColor=colors.white, alignment=1,
        ),
    }
    return s


def badge_table(disposition: str, st) -> Table:
    kind = classify(disposition)
    label = Paragraph(f"<b>{html.escape(kind)}</b>", st["badge"])
    t = Table([[label]], colWidths=[22 * mm])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), BADGE[kind]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return t


def requirement_block(row: Row, headers: list[str], st, width: float):
    """One requirement, as a block rather than a table row."""
    cells = row.cells
    ident = cells[0] if cells else ""
    requirement = cells[1] if len(cells) > 1 else ""

    five_col = len(cells) >= 5
    instrument = cells[2] if len(cells) > 2 else ""
    disposition = cells[3] if five_col else ""
    evidence = cells[4] if five_col else (cells[3] if len(cells) > 3 else "")
    evidence_label = headers[4] if five_col and len(headers) > 4 else (
        headers[3] if len(headers) > 3 else "Detail"
    )

    # `inline`, not `escape`: the roadmap section carries its own markup in
    # the identifier cell (e.g. "**R1 Resource registry** - done"), and
    # escaping it would print the asterisks.
    head = Paragraph(
        f'<font color="#1f3a5f">{inline(ident)}</font> &nbsp; '
        f"<b>{inline(requirement)}</b>",
        st["req"],
    )

    if five_col:
        header_row = Table(
            [[head, badge_table(disposition, st)]],
            colWidths=[width - 24 * mm, 24 * mm],
        )
        header_row.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (0, 0), "TOP"),
                    ("VALIGN", (1, 0), (1, 0), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        parts = [header_row]
    else:
        parts = [head]

    if instrument:
        parts.append(Paragraph("INSTRUMENT", st["label"]))
        parts.append(Paragraph(inline(instrument), st["body"]))
    if five_col and disposition:
        parts.append(Paragraph("DISPOSITION", st["label"]))
        parts.append(Paragraph(inline(disposition), st["body"]))
    if evidence:
        parts.append(Paragraph(evidence_label.upper(), st["label"]))
        parts.append(Paragraph(inline(evidence), st["body"]))
    parts.append(Spacer(1, 7))

    # Keep a short block whole; let a long one break rather than leaving a
    # near-empty page before it.
    plain_len = len(strip_markdown(evidence))
    return KeepTogether(parts) if plain_len < 700 else parts


def build(doc_model: Document, out: Path, prov: dict[str, str]) -> None:
    st = styles()
    page_w, page_h = A4
    lm = rm = 18 * mm
    tm = 16 * mm
    bm = 18 * mm
    frame_w = page_w - lm - rm

    def decorate(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.2)
        canvas.setFillColor(MUTED)
        canvas.drawString(lm, bm - 8 * mm, f"{SOURCE.relative_to(REPO)} @ {prov['commit']}")
        canvas.drawRightString(page_w - rm, bm - 8 * mm, f"Page {canvas.getPageNumber()}")
        canvas.setStrokeColor(RULE)
        canvas.setLineWidth(0.4)
        canvas.line(lm, bm - 5.5 * mm, page_w - rm, bm - 5.5 * mm)
        canvas.restoreState()

    template = PageTemplate(
        id="body",
        frames=[Frame(lm, bm, frame_w, page_h - tm - bm, id="f", showBoundary=0)],
        onPage=decorate,
    )
    pdf = BaseDocTemplate(
        str(out),
        pagesize=A4,
        pageTemplates=[template],
        title=doc_model.title,
        author="AIP / VANIAN",
        subject="RBI ecosystem requirements coverage",
    )

    story = []

    # Cover
    story.append(Paragraph(inline(doc_model.title), st["title"]))
    story.append(
        Paragraph(
            f"Rendered {prov['rendered']} from <font face='Courier' size='8.5'>"
            f"{SOURCE.relative_to(REPO)}</font><br/>"
            f"commit <font face='Courier' size='8.5'>{prov['commit']}</font> "
            f"on <font face='Courier' size='8.5'>{prov['branch']}</font> "
            f"({prov['tree']})",
            st["subtitle"],
        )
    )

    # Tally, so the first page states the shape of the claim.
    tally: dict[str, int] = {}
    for section in doc_model.sections:
        if len(section.headers) >= 5:
            for r in section.rows:
                if len(r.cells) >= 5:
                    tally[classify(r.cells[3])] = tally.get(classify(r.cells[3]), 0) + 1
    if tally:
        order = ["EXISTS", "DONE", "PARTIAL", "INTEGRATE", "BUILD", "OWNER"]
        cells = [[Paragraph(f"<b>{k}</b>", st["badge"]) for k in order if k in tally],
                 [Paragraph(f"<b>{tally[k]}</b>", st["req"]) for k in order if k in tally]]
        w = frame_w / max(1, len(cells[0]))
        t = Table(cells, colWidths=[w] * len(cells[0]))
        style = [
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("BOX", (0, 0), (-1, -1), 0.4, RULE),
            ("INNERGRID", (0, 0), (-1, -1), 0.4, RULE),
        ]
        for i, k in enumerate([k for k in order if k in tally]):
            style.append(("BACKGROUND", (i, 0), (i, 0), BADGE[k]))
        t.setStyle(TableStyle(style))
        story.append(t)
        story.append(Spacer(1, 5))
        # The legend below defines the source document's four dispositions.
        # Two of the badge words above are rendering categories rather than
        # source vocabulary, so they are defined here; a tally a reader
        # cannot decode is the same defect as a status label that disagrees
        # with its evidence.
        story.append(
            Paragraph(
                "Counts cover the "
                f"{sum(tally.values())} requirements carrying a disposition. "
                "<b>EXISTS</b>, <b>BUILD</b> and <b>INTEGRATE</b> are the source "
                "document's own words, defined below. <b>DONE</b> marks a row the "
                "source records as delivered against this roadmap; <b>PARTIAL</b> "
                "marks a row claiming both a closed and an open half (for example "
                "\u201cDONE (mechanism) / INTEGRATE (placement)\u201d), counted as "
                "open rather than closed so the tally cannot overstate readiness. "
                "Section G rows name an owner instead of a disposition and are "
                "excluded.",
                st["note"],
            )
        )
        story.append(Spacer(1, 10))

    # Legend
    if doc_model.legend:
        story.append(Paragraph("How to read a disposition", st["h2"]))
        for para in doc_model.legend:
            if not para:
                continue
            if para.startswith("-"):
                story.append(
                    Paragraph(
                        f"\u2022 {inline(para.lstrip('- ').strip())}",
                        st["legend_item"],
                    )
                )
            else:
                story.append(Paragraph(inline(para), st["legend"]))

    story.append(PageBreak())

    # Sections
    for section in doc_model.sections:
        if not section.rows:
            continue
        story.append(Paragraph(inline(section.title), st["h2"]))
        for row in section.rows:
            block = requirement_block(row, section.headers, st, frame_w)
            if isinstance(block, list):
                story.extend(block)
            else:
                story.append(block)

    # Closing prose
    if doc_model.closing:
        story.append(Paragraph("Reading this matrix", st["h2"]))
        for para in doc_model.closing:
            if para.startswith("|") or para.startswith("#"):
                continue
            story.append(Paragraph(inline(para), st["legend"]))

    pdf.build(story)


def main() -> int:
    if not SOURCE.exists():
        print(f"FATAL: {SOURCE} not found", file=sys.stderr)
        return 1
    out = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUT
    model = parse(SOURCE.read_text(encoding="utf-8"))
    prov = provenance()
    build(model, out, prov)
    rows = sum(len(s.rows) for s in model.sections)
    print(f"wrote {out.relative_to(REPO) if out.is_relative_to(REPO) else out}")
    print(f"  {len(model.sections)} sections, {rows} rows, commit {prov['commit']} ({prov['tree']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
