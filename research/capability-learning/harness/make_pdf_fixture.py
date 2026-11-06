#!/usr/bin/env python3
"""Build the synthetic maintenance-manual PDF the ingestion tests use.

Deterministic: fixed content, no randomness, no timestamp in the output, so
the same bytes are produced on every machine and the fixture can be hashed.

Structure, chosen to exercise exactly what the ingestion contract promises:

  pages 1-18   text layer, several clauses each, with the thresholds the
               atomic pipeline would draft from
  page 19      a table, rendered as spaced text the way a real manual's
               table appears to a text extractor
  page 20      IMAGE ONLY - rasterised text with no text layer at all, so
               ingestion must fall back to OCR or report that it cannot

Page 20 is the point of the fixture. A test that only feeds text-layer pages
never discovers that a scanned page is silently dropped.

The text pages are written as raw PDF rather than with a layout library: this
is a 20-page synthetic fixture, and a reportlab-class dependency for it would
be carried by every install forever.
"""
from __future__ import annotations

import argparse
import io
import sys
import zlib
from pathlib import Path

#: The clause bodies. Page 19's table and page 20's scanned text are separate.
BODY_PAGES: list[list[str]] = [
    ["EP-114 Section 1. This procedure governs insulation resistance testing "
     "of medium-voltage motors.",
     "It applies to every motor rated above 1 kV.",
     "Records shall be retained for seven years."],
    ["EP-114 Section 2. Winding temperature at the time of test shall be "
     "between 10 C and 25 C.",
     "If the winding temperature is outside the allowed range, the test shall "
     "be deferred and the deviation recorded.",
     "Temperature shall be measured at the stator winding, not at the frame."],
    ["EP-114 Section 3. The minimum insulation resistance for a 6.6 kV motor "
     "is 7.6 megohm.",
     "The value is derived as rated kilovolts plus one, in megohm, at 40 C.",
     "A reading below the minimum requires human review before any release."],
    ["EP-114 Section 4. Polarisation index shall be at least 2.0 for class F "
     "insulation.",
     "An index below 2.0 is not by itself grounds for rejection.",
     "The index shall be reported alongside the one-minute reading."],
]
# Pad to 18 text pages with numbered continuation sections, so the fixture is
# genuinely 20 pages without 18 hand-written pages of prose.
while len(BODY_PAGES) < 18:
    n = len(BODY_PAGES) + 1
    BODY_PAGES.append([
        f"EP-114 Section {n}. Continuation clause {n} of the synthetic "
        f"procedure, retained so the fixture spans twenty pages.",
        f"Clause {n}.1 states no threshold and is expected to yield no field.",
    ])

TABLE_PAGE = [
    "EP-114 Annex A. Minimum insulation resistance by rated voltage.",
    "Rated kV    Minimum megohm    Test voltage V",
    "3.3         4.3               2500",
    "6.6         7.6               5000",
    "11.0        12.0              5000",
    "Values in this annex are at 40 C and supersede any value in the body text.",
]
#: Rendered to an image, so it has NO text layer. OCR must recover it.
SCANNED_PAGE = [
    "EP-114 Annex B (scanned insert).",
    "Where a motor has been rewound, the minimum",
    "insulation resistance is 10.0 megohm regardless",
    "of rated voltage, and human review is mandatory.",
]


def _escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _content_stream(lines: list[str]) -> bytes:
    parts = ["BT", "/F1 11 Tf", "14 TL", "1 0 0 1 56 742 Tm"]
    for line in lines:
        # Wrap long clauses so the extracted text resembles a real manual's.
        remaining = line
        while remaining:
            chunk, remaining = remaining[:78], remaining[78:]
            if remaining and not remaining[0].isspace() and " " in chunk:
                cut = chunk.rindex(" ")
                chunk, remaining = chunk[:cut], chunk[cut + 1:] + remaining
            parts.append(f"({_escape(chunk)}) Tj")
            parts.append("T*")
        parts.append("T*")
    parts.append("ET")
    return "\n".join(parts).encode("latin-1", "replace")


def _scanned_page_pdf() -> bytes:
    """One image-only page, via Pillow. No text layer by construction."""
    try:
        from PIL import Image, ImageDraw
    except ImportError as error:
        raise SystemExit("make_pdf_fixture: Pillow is required to render the "
                         "scanned page: run deploy/syntriass/setup_env.sh") from error
    # 300 dpi Letter, matching the OCR_DPI the ingester rasterises at.
    # The default bitmap font is far too small at this resolution, so each
    # line is drawn small and scaled up: tesseract needs readable glyph sizes.
    image = Image.new("L", (2550, 3300), color=255)
    draw = ImageDraw.Draw(image)
    y = 300
    for line in SCANNED_PAGE:
        small = Image.new("L", (420, 16), color=255)
        ImageDraw.Draw(small).text((1, 2), line, fill=0)
        big = small.resize((420 * 6, 16 * 6), Image.LANCZOS)
        image.paste(big, (150, y))
        y += 170
    buffer = io.BytesIO()
    image.save(buffer, format="PDF", resolution=300.0)
    return buffer.getvalue()


def build(out: Path) -> Path:
    """Write the fixture and return its path."""
    pages = [*BODY_PAGES, TABLE_PAGE]
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    page_ids: list[int] = []
    content_ids: list[int] = []
    for lines in pages:
        compressed = zlib.compress(_content_stream(lines))
        content_ids.append(add(
            b"<< /Length " + str(len(compressed)).encode() +
            b" /Filter /FlateDecode >>\nstream\n" + compressed + b"\nendstream"))
        page_ids.append(0)  # filled once the Pages object id is known
    pages_id = len(objects) + len(pages) + 1
    for position, content_id in enumerate(content_ids):
        page_ids[position] = add(
            b"<< /Type /Page /Parent " + str(pages_id).encode() +
            b" /MediaBox [0 0 612 792] /Resources << /Font << /F1 " +
            str(font).encode() + b" 0 R >> >> /Contents " +
            str(content_id).encode() + b" 0 R >>")
    kids = b" ".join(str(i).encode() + b" 0 R" for i in page_ids)
    add(b"<< /Type /Pages /Kids [" + kids + b"] /Count " +
        str(len(page_ids)).encode() + b" >>")
    catalog = add(b"<< /Type /Catalog /Pages " + str(pages_id).encode() + b" 0 R >>")

    body = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(body))
        body += str(number).encode() + b" 0 obj\n" + obj + b"\nendobj\n"
    xref_at = len(body)
    body += b"xref\n0 " + str(len(objects) + 1).encode() + b"\n"
    body += b"0000000000 65535 f \n"
    for offset in offsets:
        body += f"{offset:010d} 00000 n \n".encode()
    body += (b"trailer\n<< /Size " + str(len(objects) + 1).encode() +
             b" /Root " + str(catalog).encode() + b" 0 R >>\nstartxref\n" +
             str(xref_at).encode() + b"\n%%EOF\n")

    # Append the image-only page with pypdf, so the result is one document
    # whose last page genuinely has no text layer.
    from pypdf import PdfReader, PdfWriter

    writer = PdfWriter()
    for page in PdfReader(io.BytesIO(bytes(body))).pages:
        writer.add_page(page)
    for page in PdfReader(io.BytesIO(_scanned_page_pdf())).pages:
        writer.add_page(page)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as stream:
        writer.write(stream)
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("out", type=Path)
    path = build(parser.parse_args().out)
    print(f"make_pdf_fixture: wrote {path}")
    sys.exit(0)
