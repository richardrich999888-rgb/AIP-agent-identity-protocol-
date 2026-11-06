#!/usr/bin/env python3
"""Tests for document ingestion (A1).

The contract: clauses with a page number and an exact character span, from
PDF (text layer and image-only pages), DOCX and TXT, using only local tools.

The invariant worth most: `page_text[char_start:char_end] == clause.text`.
A citation whose span does not slice back out of the page is a citation a
human cannot check, which is the whole purpose of carrying one.

The second: an OCR'd clause is labelled `pdf_ocr`, never folded into
`pdf_text`. OCR misreads digits and this pipeline drafts thresholds from
clause text, so the two cannot carry equal authority.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
HARNESS = ROOT / "research/capability-learning/harness"
sys.path.insert(0, str(HARNESS))

from ingest_documents import (TEXT_LAYER_MIN_CHARS, Clause, IngestError,  # noqa: E402
                              ingest, split_clauses)
import make_pdf_fixture  # noqa: E402

pypdf = pytest.importorskip("pypdf", reason="pypdf comes from requirements.lock")

OCR_AVAILABLE = shutil.which("pdftoppm") and shutil.which("tesseract")


@pytest.fixture(scope="module")
def manual(tmp_path_factory):
    """The 20-page fixture, built once."""
    out = tmp_path_factory.mktemp("fixture") / "ep114.pdf"
    return make_pdf_fixture.build(out)


@pytest.fixture(scope="module")
def clauses(manual):
    if not OCR_AVAILABLE:
        pytest.skip("pdftoppm/tesseract absent; the scanned page cannot be read")
    return ingest(manual)


class TestFixtureIsWhatItClaims:
    """If the fixture is wrong the rest of the file proves nothing."""

    def test_it_has_twenty_pages(self, manual):
        assert len(pypdf.PdfReader(str(manual)).pages) == 20

    def test_the_last_page_has_no_text_layer_at_all(self, manual):
        pages = pypdf.PdfReader(str(manual)).pages
        body = (pages[19].extract_text() or "").replace(" ", "").strip()
        assert body == "", (
            "page 20 must be image-only; otherwise the OCR path is never exercised")

    def test_the_text_pages_do_have_a_text_layer(self, manual):
        pages = pypdf.PdfReader(str(manual)).pages
        for index in (0, 1, 18):
            body = (pages[index].extract_text() or "").replace(" ", "").strip()
            assert len(body) >= TEXT_LAYER_MIN_CHARS, index

    def test_it_is_byte_reproducible(self, tmp_path):
        """Two builds must agree, or the fixture cannot be hashed or trusted."""
        first = make_pdf_fixture.build(tmp_path / "a.pdf").read_bytes()
        second = make_pdf_fixture.build(tmp_path / "b.pdf").read_bytes()
        assert first == second


class TestSpansAreExact:
    def test_every_span_slices_back_out_of_its_page(self, manual, clauses):
        """The invariant. A span that does not slice back is not a citation."""
        reader = pypdf.PdfReader(str(manual))
        from ingest_documents import _ocr_page
        for clause in clauses:
            if clause.extraction == "pdf_text":
                page_text = reader.pages[clause.page - 1].extract_text() or ""
            else:
                page_text = _ocr_page(manual, clause.page)
            assert page_text[clause.char_start:clause.char_end] == clause.text, (
                f"span does not match on page {clause.page}: {clause.citation}")

    def test_spans_are_ordered_and_do_not_overlap_within_a_page(self, clauses):
        by_page: dict[int, list[Clause]] = {}
        for clause in clauses:
            by_page.setdefault(clause.page, []).append(clause)
        for page, items in by_page.items():
            previous_end = -1
            for clause in items:
                assert clause.char_start >= previous_end, f"overlap on page {page}"
                assert clause.char_end > clause.char_start
                previous_end = clause.char_end

    def test_no_clause_is_blank_or_whitespace_only(self, clauses):
        for clause in clauses:
            assert clause.text.strip() == clause.text
            assert clause.text

    def test_indices_are_unique_and_contiguous(self, clauses):
        assert [c.index for c in clauses] == list(range(len(clauses)))


class TestPageNumbers:
    def test_pages_are_one_based_and_within_range(self, clauses):
        assert min(c.page for c in clauses) == 1
        assert max(c.page for c in clauses) == 20

    def test_a_known_clause_is_attributed_to_the_right_page(self, clauses):
        """Page 2 carries the temperature range in the fixture.

        Whitespace is normalised for this assertion, and that is a finding
        rather than a convenience: PDF line wrapping puts newlines inside
        phrases, so the extracted clause reads "between 10\nC and 25 C". The
        span is exact (TestSpansAreExact proves it) and the ingester is right
        to report what the page says, but any downstream quantity parser must
        treat an intra-phrase newline as a space or it will miss the value.
        """
        page_two = " ".join(c.text for c in clauses if c.page == 2)
        normalised = " ".join(page_two.split())
        assert "10 C and 25 C" in normalised

    def test_clause_text_can_contain_newlines_from_pdf_wrapping(self, clauses):
        """Pinned deliberately, so the wrapping behaviour is not a surprise
        to whoever writes the field parser."""
        assert any("\n" in c.text for c in clauses if c.extraction == "pdf_text")

    def test_the_page_filter_returns_only_that_page(self, manual):
        only = ingest(manual, pages=[3])
        assert only
        assert {c.page for c in only} == {3}

    def test_the_annex_table_rows_survive_extraction(self, clauses):
        page_nineteen = " ".join(c.text for c in clauses if c.page == 19)
        for row in ("3.3", "6.6", "11.0", "Test voltage"):
            assert row in page_nineteen, row


@pytest.mark.skipif(not OCR_AVAILABLE, reason="pdftoppm/tesseract absent")
class TestScannedPage:
    def test_the_scanned_page_produced_clauses(self, clauses):
        """Without this, a scanned page is silently dropped."""
        assert [c for c in clauses if c.page == 20]

    def test_they_are_labelled_pdf_ocr_not_pdf_text(self, clauses):
        """The discipline: OCR'd text cannot carry text-layer authority."""
        for clause in clauses:
            expected = "pdf_ocr" if clause.page == 20 else "pdf_text"
            assert clause.extraction == expected, clause.citation

    def test_ocr_recovered_the_threshold_on_that_page(self, clauses):
        recovered = " ".join(c.text for c in clauses if c.page == 20)
        assert "10.0" in recovered, (
            "the scanned annex states 10.0 megohm; a lost digit is the exact "
            "failure the pdf_ocr label warns about")
        assert "rewound" in recovered

    def test_missing_ocr_tools_are_refused_not_skipped(self, manual, monkeypatch):
        """A silently skipped scanned page is a clause the expert never sees."""
        import ingest_documents
        monkeypatch.setattr(ingest_documents.shutil, "which", lambda name: None)
        with pytest.raises(IngestError) as caught:
            ingest_documents.ingest(manual)
        message = str(caught.value)
        assert "no text layer" in message
        assert "poppler-utils" in message or "tesseract-ocr" in message


class TestOtherFormats:
    def test_txt_is_ingested_as_one_page(self, tmp_path):
        path = tmp_path / "note.txt"
        path.write_text("First clause here. Second clause follows.\n\nThird one.\n")
        clauses = ingest(path)
        assert {c.page for c in clauses} == {1}
        assert {c.extraction for c in clauses} == {"txt"}
        body = path.read_text()
        for clause in clauses:
            assert body[clause.char_start:clause.char_end] == clause.text

    def test_docx_paragraphs_and_table_cells_are_both_captured(self, tmp_path):
        docx = pytest.importorskip("docx", reason="python-docx comes from requirements.lock")
        path = tmp_path / "policy.docx"
        document = docx.Document()
        document.add_paragraph("Policy clause one states the limit is 25 C.")
        table = document.add_table(rows=2, cols=2)
        table.rows[0].cells[0].text = "Rated kV"
        table.rows[0].cells[1].text = "Minimum megohm"
        table.rows[1].cells[0].text = "6.6"
        table.rows[1].cells[1].text = "7.6"
        document.save(str(path))
        clauses = ingest(path)
        text = " ".join(c.text for c in clauses)
        assert "25 C" in text
        assert "6.6" in text and "7.6" in text
        assert {c.extraction for c in clauses} == {"docx"}

    def test_an_unsupported_type_is_refused_with_the_accepted_list(self, tmp_path):
        path = tmp_path / "sheet.xlsx"
        path.write_bytes(b"not really a spreadsheet")
        with pytest.raises(IngestError) as caught:
            ingest(path)
        assert ".pdf" in str(caught.value)

    def test_a_missing_document_is_refused(self, tmp_path):
        with pytest.raises(IngestError):
            ingest(tmp_path / "absent.pdf")

    def test_a_pdf_that_is_not_a_pdf_is_refused_not_guessed(self, tmp_path):
        path = tmp_path / "broken.pdf"
        path.write_bytes(b"%PDF-1.4 truncated and invalid")
        with pytest.raises(IngestError):
            ingest(path)


class TestProvenance:
    def test_every_clause_carries_the_document_digest(self, clauses):
        digests = {c.document_sha256 for c in clauses}
        assert len(digests) == 1
        assert len(digests.pop()) == 64

    def test_the_digest_matches_the_file(self, manual, clauses):
        import hashlib
        assert clauses[0].document_sha256 == hashlib.sha256(manual.read_bytes()).hexdigest()

    def test_the_citation_names_document_page_and_span(self, clauses):
        citation = clauses[0].citation
        assert "p." in citation and "[" in citation and ":" in citation


class TestClauseSplitting:
    """Pure, no document needed."""

    def test_sentences_split_on_terminators(self):
        text = "One. Two. Three."
        assert len(split_clauses(text)) == 3

    def test_blank_lines_split_paragraphs(self):
        assert len(split_clauses("Para one\n\nPara two")) == 2

    def test_empty_and_whitespace_input_yield_nothing(self):
        for text in ("", "   ", "\n\n\n"):
            assert split_clauses(text) == []

    def test_a_decimal_point_does_not_split_a_number(self):
        """'7.6 megohm' must stay one clause; the threshold is the payload."""
        spans = split_clauses("The minimum is 7.6 megohm at 40 C.")
        assert len(spans) == 1

    def test_spans_slice_back_out_of_the_input(self):
        text = "Alpha clause. Beta clause.\n\nGamma clause."
        for start, end in split_clauses(text):
            assert text[start:end].strip() == text[start:end]


class TestCommandLine:
    def test_it_writes_json_with_extraction_counts_and_the_ocr_note(self, manual, tmp_path):
        if not OCR_AVAILABLE:
            pytest.skip("pdftoppm/tesseract absent")
        out = tmp_path / "clauses.json"
        result = subprocess.run(
            [sys.executable, "-I", str(HARNESS / "ingest_documents.py"),
             str(manual), "--out", str(out)],
            capture_output=True, text=True, timeout=900)
        assert result.returncode == 0, result.stderr
        payload = json.loads(out.read_text())
        assert payload["clause_count"] == len(payload["clauses"])
        assert payload["extraction_counts"]["pdf_ocr"] >= 1
        assert "OCR" in payload["provenance_note"]

    def test_a_missing_document_exits_three(self, tmp_path):
        result = subprocess.run(
            [sys.executable, "-I", str(HARNESS / "ingest_documents.py"),
             str(tmp_path / "absent.pdf")],
            capture_output=True, text=True, timeout=120)
        assert result.returncode == 3
        assert "ingest:" in result.stderr
