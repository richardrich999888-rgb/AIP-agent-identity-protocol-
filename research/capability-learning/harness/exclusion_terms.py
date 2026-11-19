"""Bounded, explicit word-form choices for maintenance exclusions only.

This is a reviewed vocabulary, not stemming or a model inference. A variant
is offered only when its paired term occurs whole in the cited sentence.
Selecting it must retain that quoted term in the same answer. Nothing is
added automatically, and this policy cannot authorize a subject or input cue.
Unknown equipment remains literal-only until a separate vocabulary review.
"""
from __future__ import annotations

import re

POLICY = "syntriass.maintenance-exclusion-word-forms/v1"
PAIRS = (
    ("motor", "motors"),
    ("cable", "cables"),
    ("generator", "generators"),
    ("dry-type transformer", "dry-type transformers"),
)


def in_quote(term: str, quote: str) -> bool:
    return re.search(rf"(?<!\w){re.escape(term)}(?!\w)", quote, re.IGNORECASE) is not None


def offered(quote: str) -> list[dict]:
    """Return explicit source -> variant choices; preserve the source's case."""
    choices = []
    for pair in PAIRS:
        for source, term in (pair, pair[::-1]):
            match = re.search(rf"(?<!\w){re.escape(source)}(?!\w)", quote, re.IGNORECASE)
            if match and not in_quote(term, quote):
                choices.append({"source_term": match.group(), "term": term, "policy": POLICY})
    return choices


def selected(term: str, quote: str) -> dict | None:
    return next((c for c in offered(quote) if c["term"].casefold() == term.casefold()), None)


def errors(terms: list[str], quote: str) -> list[str]:
    """Check the same choices shown by B1; additions must retain their source."""
    present = {term.casefold() for term in terms}
    problems = []
    for term in terms:
        if not term.strip():
            problems.append("an empty term teaches nothing")
        elif not in_quote(term, quote):
            choice = selected(term, quote)
            if choice is None:
                problems.append(f"term {term!r} is not written in the quoted sentence "
                                "and is not an offered exclusion word form")
            elif choice["source_term"].casefold() not in present:
                problems.append(f"term {term!r} requires keeping quoted term "
                                f"{choice['source_term']!r} in the same answer")
    return problems
