#!/usr/bin/env python3
"""Turn a real document into citable clauses for the atomic pipeline.

Accepts PDF (text layer, and image-only pages via local OCR), DOCX and TXT.
Every clause carries the page it came from and the exact character span it
occupies in that page's text, so a capability drafted from it can cite a
location a human can check.

## The distinction this module exists to preserve

A clause read from a PDF's text layer and a clause recovered by OCR are not
the same kind of fact. OCR misreads digits, and this pipeline drafts
*thresholds* from clause text — "25 °C" and "26 °C" differ by one glyph. So
`Clause.extraction` is part of every clause and OCR'd text is labelled
`pdf_ocr`, never folded into `pdf_text`. Downstream, an OCR'd value belongs in
the `hypothesis` class that gets a question put to the expert, not in
`evidence`.

Nothing here classifies, repairs or decides. It reports what the document
says and where, and refuses rather than guesses when it cannot read a page.

## Offline

Uses only local tools: `pypdf` for the text layer, and for an image-only page
`pdftoppm` (poppler-utils) plus `tesseract`. No network call, no model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

#: A page whose text layer yields fewer than this many non-space characters is
#: treated as image-only and sent to OCR. Scanned pages typically yield zero;
#: the margin covers a stray header picked up from an image-only page.
TEXT_LAYER_MIN_CHARS = 24

#: Clause boundaries: a blank line, or a sentence terminator followed by
#: whitespace. Deterministic and offset-preserving — the span of every clause
#: is sliced straight out of the page text, never rebuilt from tokens.
_BOUNDARY = re.compile(r"(?:\n\s*\n)|(?<=[.;:!?])\s+")

#: OCR resolution. 300 dpi is the usual floor for reliable digit recognition;
#: recorded here because changing it changes what OCR reads.
OCR_DPI = 300


class IngestError(Exception):
    """The document could not be read. Never downgraded to a partial result."""


@dataclass(frozen=True)
class Clause:
    """One citable span of a document."""

    document: str
    document_sha256: str
    page: int
    index: int
    text: str
    char_start: int
    char_end: int
    #: "pdf_text" | "pdf_ocr" | "docx" | "txt". Part of the clause because an
    #: OCR'd threshold must not be trusted like a read one.
    extraction: str

    @property
    def citation(self) -> str:
        return f"{self.document} p.{self.page} [{self.char_start}:{self.char_end}]"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def split_clauses(page_text: str) -> list[tuple[int, int]]:
    """Clause spans as (start, end) offsets into `page_text`.

    Returns offsets rather than strings so the caller slices the original and
    the span is exact by construction. A test asserts
    `page_text[start:end] == clause.text` for every clause.
    """
    spans: list[tuple[int, int]] = []
    cursor = 0
    for match in _BOUNDARY.finditer(page_text):
        start, end = cursor, match.start()
        if page_text[start:end].strip():
            spans.append(_tighten(page_text, start, end))
        cursor = match.end()
    if page_text[cursor:].strip():
        spans.append(_tighten(page_text, cursor, len(page_text)))
    return spans


def _tighten(text: str, start: int, end: int) -> tuple[int, int]:
    """Trim surrounding whitespace without losing offset accuracy."""
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    return start, end


def _ocr_page(pdf: Path, page_number: int) -> str:
    """Rasterise one page and read it with tesseract.

    Both tools are local. A missing tool is a refusal naming the package,
    because a silently skipped scanned page is a clause the expert never sees.
    """
    for tool, package in (("pdftoppm", "poppler-utils"), ("tesseract", "tesseract-ocr")):
        if shutil.which(tool) is None:
            raise IngestError(
                f"page {page_number} of {pdf.name} has no text layer and OCR is "
                f"unavailable: '{tool}' not found (install {package}; an "
                f"air-gapped bundle must carry its .deb).")
    with tempfile.TemporaryDirectory() as temporary:
        stem = Path(temporary) / "page"
        raster = subprocess.run(
            ["pdftoppm", "-r", str(OCR_DPI), "-f", str(page_number),
             "-l", str(page_number), "-png", str(pdf), str(stem)],
            capture_output=True, text=True, timeout=300)
        if raster.returncode:
            raise IngestError(f"pdftoppm failed on page {page_number} of "
                              f"{pdf.name}: {raster.stderr.strip()[:300]}")
        images = sorted(Path(temporary).glob("page*.png"))
        if not images:
            raise IngestError(f"pdftoppm produced no image for page {page_number} "
                              f"of {pdf.name}")
        read = subprocess.run(["tesseract", str(images[0]), "stdout", "--dpi",
                               str(OCR_DPI)],
                              capture_output=True, text=True, timeout=600)
        if read.returncode:
            raise IngestError(f"tesseract failed on page {page_number} of "
                              f"{pdf.name}: {read.stderr.strip()[:300]}")
        return read.stdout


def _pdf_pages(path: Path) -> list[tuple[str, str]]:
    """(page_text, extraction) per page, OCR'ing pages with no text layer."""
    try:
        from pypdf import PdfReader
    except ImportError as error:
        raise IngestError("pypdf is required to read PDF: "
                          "run deploy/syntriass/setup_env.sh") from error
    try:
        reader = PdfReader(str(path))
    except Exception as error:  # pypdf raises several unrelated types
        raise IngestError(f"{path.name} could not be opened as a PDF: {error}") from error
    pages = []
    for number, page in enumerate(reader.pages, start=1):
        try:
            text = page.extract_text() or ""
        except Exception as error:
            raise IngestError(f"{path.name} page {number}: text extraction "
                              f"failed: {error}") from error
        if len(text.replace(" ", "").strip()) >= TEXT_LAYER_MIN_CHARS:
            pages.append((text, "pdf_text"))
        else:
            pages.append((_ocr_page(path, number), "pdf_ocr"))
    return pages


def _docx_pages(path: Path) -> list[tuple[str, str]]:
    """DOCX has no pages until it is laid out, so the whole body is page 1.

    Said plainly rather than invented: a page number guessed from paragraph
    counts would be a citation that does not check out against the file.
    """
    try:
        import docx
    except ImportError as error:
        raise IngestError("python-docx is required to read DOCX: "
                          "run deploy/syntriass/setup_env.sh") from error
    document = docx.Document(str(path))
    blocks = [paragraph.text for paragraph in document.paragraphs if paragraph.text.strip()]
    for table in document.tables:
        for row in table.rows:
            cells = [cell.text.strip() for cell in row.cells]
            if any(cells):
                blocks.append(" | ".join(cells))
    return [("\n\n".join(blocks), "docx")]


def ingest(path: Path, *, pages: list[int] | None = None) -> list[Clause]:
    """Clauses from one document, optionally restricted to 1-based `pages`."""
    path = Path(path)
    if not path.is_file():
        raise IngestError(f"no such document: {path}")
    suffix = path.suffix.lower()
    if suffix == ".pdf":
        page_texts = _pdf_pages(path)
    elif suffix == ".docx":
        page_texts = _docx_pages(path)
    elif suffix in (".txt", ".text"):
        page_texts = [(path.read_text(errors="replace"), "txt")]
    else:
        raise IngestError(f"unsupported document type '{suffix}' for {path.name}; "
                          f"accepted: .pdf, .docx, .txt")
    digest = sha256_file(path)
    clauses: list[Clause] = []
    for number, (text, extraction) in enumerate(page_texts, start=1):
        if pages is not None and number not in pages:
            continue
        for start, end in split_clauses(text):
            clauses.append(Clause(
                document=path.name, document_sha256=digest, page=number,
                index=len(clauses), text=text[start:end],
                char_start=start, char_end=end, extraction=extraction))
    return clauses


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("document", type=Path)
    parser.add_argument("--page", type=int, action="append", dest="pages",
                        help="restrict to this 1-based page (repeatable)")
    parser.add_argument("--out", type=Path, help="write JSON here instead of stdout")
    args = parser.parse_args(argv)
    try:
        clauses = ingest(args.document, pages=args.pages)
    except IngestError as error:
        print(f"ingest: {error}", file=sys.stderr)
        return 3
    payload = {
        "document": args.document.name,
        "document_sha256": clauses[0].document_sha256 if clauses else sha256_file(args.document),
        "clause_count": len(clauses),
        "extraction_counts": {kind: sum(1 for c in clauses if c.extraction == kind)
                              for kind in sorted({c.extraction for c in clauses})},
        "provenance_note": ("Clauses marked pdf_ocr were recovered by OCR, not read "
                            "from a text layer. OCR misreads digits, and this pipeline "
                            "drafts thresholds from clause text, so an OCR'd value "
                            "belongs in the hypothesis class that is put to the expert."),
        "clauses": [asdict(clause) for clause in clauses],
    }
    text = json.dumps(payload, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
        print(f"ingest: {len(clauses)} clauses -> {args.out}")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
