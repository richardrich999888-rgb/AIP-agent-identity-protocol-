"""Atomic-claim acquisition: document → cited claims → typed IR → checks.

Pure and deterministic (no IO, no model). The IO driver is
`propose_atomic.py`; the model only answers small per-clause questions whose
answer schema is built here from that clause alone.

Pipeline (v0.2, phase 1):
1. `segment` splits the procedure into numbered clauses with character spans
   (the citation unit).
2. `clause_numbers` extracts every number literally stated in a clause, typed
   by the unit word that follows it. A claim's numeric fields are JSON-schema
   enums of exactly these numbers, so an unsupported constant cannot be
   expressed at all (not merely detected afterwards).
3. The model classifies each clause and fills one typed claim per kind.
4. `verify_claim` checks each claim against its clause with fixed lexicons
   (comparators, units, fractions, outcome words). A field is
   - "evidence"   when the clause determines it uniquely and the model agrees,
   - "repaired"   when the clause determines it uniquely and the model
                  disagreed (the clause value is used; the repair is recorded),
   - "hypothesis" when the clause admits several values (model's choice kept),
   - an issue     when the model's value is not supported at all.
5. `assemble` builds the existing typed IR (ir_compiler) and records rule
   precedence simplifications; `consistency` runs deterministic checks with
   exact rational arithmetic (fractions.Fraction).
6. `boundary_points` generates deterministic counterexample inputs around
   every threshold; `evaluate_ir` is a reference evaluator used only to
   confirm the compiled artifact means what the IR means. Generated points
   carry NO expected labels: labels come only from the signed expert suite.

Nothing here can approve, activate or sign anything.

Assumptions and limits (stated, tested):
- clauses are sentences; a sentence is split at ". " followed by a capital;
- the lexicons are English and fixed; they were written against the two
  development families (ir-tasks-v1, bt-tasks-v1) before the holdout run;
- attempt history: 1 = model classifies every clause; 2 = kind evidence
  gates, input completion from units, validity outcome from the next
  sentence; 3 = abbreviation cues, one condition per comparator phrase,
  limit template from wording, exact probe rendering. Frozen after 3;
- one condition per rule after precedence simplification (the IR has no
  conjunction); a conjunction that precedence does not reduce is an issue.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from fractions import Fraction

from ir_compiler import OPS, PHYS_REFS, UNITS, VALUE_REFS

KINDS = ("scope_subject", "scope_exclusion_terms", "scope_limit", "required_inputs", "missing_input",
         "validity", "correction", "limit", "decision_rule", "default_outcome", "none")

# Unit words following a number → canonical IR unit symbol. Order matters
# (longest first). Used for typing numbers and for input units.
UNIT_WORDS = [
    (r"kV\b", "kV"), (r"(?:V\b|volts?\b)", "V"),
    (r"(?:GΩ|gigohms?\b)", "GΩ"), (r"(?:kΩ|kilohms?\b)", "kΩ"), (r"(?:MΩ|megohms?\b|Mohms?\b)", "MΩ"),
    (r"(?:°\s?C\b|degrees? Celsius\b)", "°C"), (r"(?:°\s?F\b|degrees? Fahrenheit\b)", "°F"),
]
# Unit mentions anywhere in a clause (for input-unit determination).
UNIT_MENTIONS = [(r"\bkV\b", "kV"), (r"\bvolts?\b", "V"), (r"\bmegohms?\b|MΩ", "MΩ"), (r"\bgigohms?\b|GΩ", "GΩ"),
                 (r"\bdegrees? Celsius\b|°C", "°C"), (r"\bdegrees? Fahrenheit\b|°F", "°F")]
UNIT_KIND = {"kV": "voltage", "V": "voltage", "MΩ": "resistance", "GΩ": "resistance", "kΩ": "resistance",
             "°C": "temperature", "°F": "temperature", "none": "cued"}
NUMBER_WORDS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
                "nine": 9, "ten": 10}
FRACTION_WORDS = [(r"\bone third\b", Fraction(1, 3)), (r"\btwo thirds\b", Fraction(2, 3)),
                  (r"\bone quarter\b", Fraction(1, 4)), (r"\b(?:one )?half\b", Fraction(1, 2))]
# Comparator phrases (longest first so "at least" wins over a bare word).
COMPARATORS = [(r"\bat least\b|\bnot less than\b|\bno less than\b", ">="),
               (r"\bat most\b|\bnot more than\b|\bno more than\b|\bup to and including\b", "<="),
               (r"\bbelow\b|\bless than\b|\bunder\b|\blower than\b", "<"),
               (r"\babove\b|\bgreater than\b|\bmore than\b|\bexceeds?\b|\bhigher than\b", ">")]
SUBJECT_WORDS = {"voltage": r"\bvoltage\b", "resistance": r"\bresistance\b", "temperature": r"\btemperature\b"}
LIMIT_WORDS = r"\bminimum\b|\bmaximum\b|\blimit\b"
SECTION_NUMBER = r"\b(?:Step|step|revision|rev)\s+\d+\b"


@dataclass(frozen=True)
class Clause:
    """A citation unit: one sentence of the procedure."""
    cid: str
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class Num:
    """A number stated in a clause, with its unit tag ('none' if unitless)."""
    value: Fraction
    unit: str
    start: int


@dataclass
class Verified:
    claim: dict
    fields: dict = field(default_factory=dict)  # field path → evidence | repaired | hypothesis
    repairs: list = field(default_factory=list)
    issues: list = field(default_factory=list)


# ── 1. segmentation ───────────────────────────────────────────────────────────

def segment(doc: str) -> list[Clause]:
    """Split a document into sentence clauses with absolute character spans.

    A sentence ends at '.' followed by whitespace and an upper-case letter or
    a line break; decimals ('2.10') never split because no space follows."""
    out: list[Clause] = []
    pos = 0
    for ln, line in enumerate(doc.split("\n")):
        k = 0
        start = 0
        for m in re.finditer(r"\.(?=\s+[A-Z(])|\.$", line):
            seg = line[start:m.end()].strip()
            if seg:
                off = pos + start + (len(line[start:]) - len(line[start:].lstrip()))
                out.append(Clause(f"L{ln}.S{k}", off, off + len(seg), seg))
                k += 1
            start = m.end()
        rest = line[start:].strip()
        if rest:
            off = pos + start + (len(line[start:]) - len(line[start:].lstrip()))
            out.append(Clause(f"L{ln}.S{k}", off, off + len(rest), rest))
        pos += len(line) + 1
    return out


# ── 2. typed numbers ──────────────────────────────────────────────────────────

def clause_numbers(text: str) -> list[Num]:
    """Every number stated in `text`: decimal literals (typed by the unit word
    that follows), number words, and fraction words. Section numbering
    ('Step 1') and identifier digits ('EP-114') are excluded."""
    masked = re.sub(SECTION_NUMBER, lambda m: " " * len(m.group()), text)
    nums: list[Num] = []
    for pat, val in FRACTION_WORDS:
        for m in re.finditer(pat, masked, re.IGNORECASE):
            nums.append(Num(val, "none", m.start()))
            masked = masked[:m.start()] + " " * (m.end() - m.start()) + masked[m.end():]
    for m in re.finditer(r"(?<![\w.\-])(\d+(?:\.\d+)?)(?![\w.]*\d)", masked):
        nums.append(Num(Fraction(m.group(1)), _unit_after(masked[m.end():]), m.start()))
    for w, v in NUMBER_WORDS.items():
        for m in re.finditer(rf"\b{w}\b", masked, re.IGNORECASE):
            nums.append(Num(Fraction(v), _unit_after(masked[m.end():]), m.start()))
    return sorted(nums, key=lambda n: n.start)


def _unit_after(s: str) -> str:
    for pat, sym in UNIT_WORDS:
        if re.match(r"\s*" + pat, s):
            return sym
    return "none"


def number_enum(nums: list[Num], extra: tuple = ()) -> list:
    """JSON enum values for a numeric field: exactly the clause's numbers
    (as floats) plus explicitly listed neutral values (0, 1)."""
    vals = sorted({float(n.value) for n in nums} | {float(x) for x in extra})
    return vals


# ── 3. per-kind answer schemas (built from one clause) ────────────────────────

def classify_schema() -> dict:
    return {"type": "object", "properties": {"kinds": {"type": "array", "items": {"enum": list(KINDS)},
                                                       "minItems": 1, "maxItems": 3}}, "required": ["kinds"]}


def claim_schema(kind: str, clause: Clause, outcomes: list[str]) -> dict:
    """Answer schema for one claim kind about one clause. Numeric fields are
    enums of the clause's own numbers."""
    nums = clause_numbers(clause.text)
    n = {"enum": number_enum(nums)} if nums else {"enum": [0.0]}
    n01 = {"enum": number_enum(nums, (0, 1))}
    out = {"enum": outcomes}
    op = {"enum": list(OPS)}
    terms = {"type": "array", "items": {"type": "string", "maxLength": 40}, "minItems": 1, "maxItems": 8}
    obj = lambda props: {"type": "object", "properties": props, "required": list(props)}
    if kind in ("scope_subject", "scope_exclusion_terms"):
        return obj({"terms": terms})
    if kind == "scope_limit":
        return obj({"ref": {"enum": list(PHYS_REFS)}, "op": op, "value": n,
                    "meaning": {"enum": ["out_of_scope_when_true", "in_scope_when_true"]}})
    if kind == "required_inputs":
        inp = obj({"ref": {"enum": ["voltage", "resistance", "temperature", "cued_1", "cued_2"]},
                   "unit": {"enum": list(UNITS)},
                   "cues": {"type": "array", "items": {"type": "string", "maxLength": 32}, "maxItems": 3}})
        return obj({"inputs": {"type": "array", "items": inp, "minItems": 1, "maxItems": 5}})
    if kind in ("missing_input", "default_outcome"):
        return obj({"outcome": out})
    if kind == "validity":
        return obj({"ref": {"enum": ["voltage", "resistance", "temperature", "cued_1", "cued_2"]}, "min": n, "max": n, "outcome": out})
    if kind == "correction":
        return obj({"template": {"enum": ["add_per_degree", "multiply_power_per_degree"]},
                    "target": {"enum": list(PHYS_REFS)}, "by": {"enum": list(PHYS_REFS)},
                    "reference": n, "rate": n01, "base": n01, "step": n01})
    if kind == "limit":
        return obj({"template": {"enum": ["constant", "coefficient_times_input_plus_offset"]},
                    "coefficient": n, "input": {"enum": list(PHYS_REFS)}, "offset": n01})
    if kind == "decision_rule":
        cond = obj({"subject": {"enum": list(VALUE_REFS)}, "op": op, "against": {"enum": ["number", "limit"]},
                    "number": n01})
        return obj({"conditions": {"type": "array", "items": cond, "minItems": 1, "maxItems": 2}, "outcome": out})
    return obj({})


# ── 3b. claim-kind evidence gates ─────────────────────────────────────────────

def plausible_kinds(text: str, outcomes: list[str]) -> list[str]:
    """Kinds a clause can support at all (necessary textual evidence for each).

    A claim of a kind not in this list has no citation and is rejected before
    any field is read. Added in attempt 2 after attempt 1 showed the 0.5B
    classifier assigning the first schema kinds to almost every clause."""
    low = text.lower()
    nums = clause_numbers(text)
    tagged = [n for n in nums if n.unit != "none"]
    cmp = comparators(text)
    k = []
    if re.match(r"\s*scope\b", low) or re.search(r"\bapplies to\b|\bcovers\b", low):
        k.append("scope_subject")
    if re.search(r"does not apply to|not covered|\bexcluded\b", low):
        k.append("scope_exclusion_terms")
    if tagged and cmp and re.search(r"scope|does not apply|\brated\b", low):
        k.append("scope_limit")
    if re.search(r"\binputs?\b", low) and (len(units_mentioned(text)) >= 2 or re.search(r"\([A-Z]{2,5}\)", text)):
        k.append("required_inputs")
    if re.search(r"\bmissing\b|\bnot (?:available|recorded|measured)\b", low):
        k.append("missing_input")
    if re.search(r"\bvalid|\binvalid", low) and len(nums) >= 2 and re.search(r"between|range|inclusive", low):
        k.append("validity")
    if re.search(r"\bcorrect\b|\bcorrected to\b", low) and re.search(r"power|\badd|subtract|multipl", low):
        k.append("correction")
    if re.search(LIMIT_WORDS, low) and re.search(r"\btimes\b|\bis\s+\d", low) and not cmp:
        k.append("limit")
    if cmp and re.search(r"\bif\b", low):
        k.append("decision_rule")
    if re.match(r"\s*otherwise\b", low) and not cmp and outcome_match(text, outcomes):
        k.append("default_outcome")
    return k


# ── 4. verification against the clause ───────────────────────────────────────

def comparators(text: str) -> list[tuple[int, str]]:
    """(position, op) of every comparator phrase, in text order, non-overlapping."""
    hits: list[tuple[int, int, str]] = []
    for pat, op in COMPARATORS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            if not any(s <= m.start() < e for s, e, _ in hits):
                hits.append((m.start(), m.end(), op))
    return [(s, op) for s, _, op in sorted(hits)]


def outcome_match(text: str, outcomes: list[str]) -> list[str]:
    """Outcome labels best supported by the clause's words.

    Score = fraction of the label's tokens present in the clause (a token
    matches a clause word sharing its first 5 letters; 'NNd' matches 'NN
    days'). Returns every label with the maximal score if that score ≥ 0.5,
    else []. Uniqueness is decided by the caller."""
    words = [w.lower() for w in re.findall(r"[A-Za-z]+", text)]
    low = text.lower()

    def tok_ok(t: str) -> bool:
        m = re.fullmatch(r"(\d+)d", t)
        if m:
            return re.search(rf"\b{m.group(1)} days?\b", low) is not None
        return any(w[:5] == t[:5] and (len(t) >= 5 or w == t) for w in words)

    scores = {}
    for o in outcomes:
        toks = [t.lower() for t in o.split("_") if t]
        scores[o] = sum(tok_ok(t) for t in toks) / len(toks)
    best = max(scores.values())
    return [o for o, s in scores.items() if s == best] if best >= 0.5 else []


def abbreviation_pairs(text: str) -> list[tuple[str, str]]:
    """(ABBR, phrase) for each 'phrase (ABBR)' whose phrase is the words whose
    initials spell ABBR (else the two preceding words). Deterministic."""
    out = []
    for m in re.finditer(r"\(([A-Z][A-Za-z]{1,4})\)", text):
        ab = m.group(1)
        words = re.findall(r"[A-Za-z][\w-]*", text[:m.start()])
        n = len(ab)
        if len(words) >= n and "".join(w[0] for w in words[-n:]).lower() == ab.lower():
            phrase = " ".join(words[-n:])
        else:
            phrase = " ".join(words[-2:])
        out.append((ab, phrase))
    return out


def units_mentioned(text: str) -> list[str]:
    return [sym for pat, sym in UNIT_MENTIONS if re.search(pat, text)]


def _set(v: Verified, path: str, status: str) -> None:
    v.fields[path] = status


def _check_value(v: Verified, path: str, model_val, determined: list, apply) -> None:
    """Common field logic: unique evidence → evidence/repaired; several → hypothesis."""
    if len(determined) == 1:
        if model_val == determined[0]:
            _set(v, path, "evidence")
        else:
            v.repairs.append({"field": path, "from": model_val, "to": determined[0], "basis": "uniquely determined by clause"})
            apply(determined[0])
            _set(v, path, "repaired")
    elif model_val in determined:
        _set(v, path, "hypothesis")
    elif determined:
        v.issues.append({"field": path, "value": model_val, "allowed": determined, "issue": "not supported by clause"})
    else:
        _set(v, path, "hypothesis")


def subject_candidates(segment_text: str, cues: dict[str, list[str]]) -> list[str]:
    """Subject of a condition: the input named closest before the comparator.
    'corrected' when the segment says so; [] when only a pronoun is used."""
    if re.search(r"\bcorrected\b", segment_text, re.IGNORECASE):
        return ["corrected"]
    hits = []
    for ref, pat in SUBJECT_WORDS.items():
        for m in re.finditer(pat, segment_text, re.IGNORECASE):
            hits.append((m.start(), ref))
    for ref, cs in cues.items():
        for c in cs:
            for m in re.finditer(rf"\b{re.escape(c)}\b", segment_text):
                hits.append((m.start(), ref))
    return [max(hits)[1]] if hits else []


def verify_claim(kind: str, claim: dict, clause: Clause, outcomes: list[str], ctx: dict) -> Verified:
    """Check one model claim against its clause. Mutates a copy of the claim
    only for uniquely determined fields. `ctx` carries cues of declared inputs
    and the previous rule subject (for pronoun resolution)."""
    import copy

    c = copy.deepcopy(claim)
    v = Verified(c)
    t = clause.text
    low = t.lower()
    nums = clause_numbers(t)
    numvals = {float(n.value) for n in nums}

    def num_ok(path, x, neutral=()):
        if float(x) not in numvals and float(x) not in neutral:
            v.issues.append({"field": path, "value": x, "issue": "number not stated in clause"})

    if kind in ("scope_subject", "scope_exclusion_terms"):
        kept = [w for w in c["terms"] if w.strip() and w.lower() in low]
        dropped = [w for w in c["terms"] if w not in kept]
        if dropped:
            v.repairs.append({"field": "terms", "from": c["terms"], "to": kept, "basis": "terms not present in clause removed"})
            c["terms"] = kept
        if not kept:
            v.issues.append({"field": "terms", "issue": "no term present in clause"})
        _set(v, "terms", "evidence" if not dropped else "repaired")
    elif kind == "scope_limit":
        num_ok("value", c["value"])
        tagged = [n for n in nums if float(n.value) == float(c["value"])]
        kinds = {UNIT_KIND[n.unit] for n in tagged if n.unit != "none"}
        _check_value(v, "ref", c["ref"], sorted(kinds), lambda x: c.__setitem__("ref", x))
        cmp = [op for _, op in comparators(t)]
        _check_value(v, "op", c["op"], sorted(set(cmp)) if len(set(cmp)) == 1 else cmp, lambda x: c.__setitem__("op", x))
        says_out = "out of scope" in low or "does not apply" in low
        _check_value(v, "meaning", c["meaning"], ["out_of_scope_when_true"] if says_out else ["in_scope_when_true"]
                     if low.startswith("scope") else [], lambda x: c.__setitem__("meaning", x))
        c["unit"] = next((n.unit for n in tagged if n.unit != "none"), "none")
    elif kind == "required_inputs":
        mentioned = units_mentioned(t)
        for k, inp in enumerate(c["inputs"]):
            kind_k = "cued" if inp["ref"].startswith("cued") else inp["ref"]
            if kind_k == "cued":
                ok = [w for w in inp["cues"] if w.strip() and re.search(rf"\b{re.escape(w)}\b", t, re.IGNORECASE)]
                if ok != inp["cues"]:
                    v.repairs.append({"field": f"inputs[{k}].cues", "from": inp["cues"], "to": ok, "basis": "cues not present in clause removed"})
                    inp["cues"] = ok
                if not ok:
                    v.issues.append({"field": f"inputs[{k}].cues", "issue": "cued input without a cue present in clause"})
                _check_value(v, f"inputs[{k}].unit", inp["unit"], ["none"], lambda x, i=inp: i.__setitem__("unit", x))
            else:
                if inp["cues"]:
                    inp["cues"] = []
                cands = [u for u in mentioned if UNIT_KIND[u] == kind_k]
                _check_value(v, f"inputs[{k}].unit", inp["unit"], cands, lambda x, i=inp: i.__setitem__("unit", x))
        # Unique-evidence completion (attempt 2): every physical quantity the
        # clause names with a unit must be declared exactly once; a cued input
        # with no cue present is unsupported and removed; a single
        # parenthesised abbreviation in the clause is the cue of a single
        # cued input that lacks one.
        before = [dict(i) for i in c["inputs"]]
        keep, seen = [], set()
        for inp in c["inputs"]:
            if inp["ref"] in seen:
                continue
            if inp["ref"].startswith("cued") and not inp["cues"]:
                continue
            seen.add(inp["ref"])
            keep.append(inp)
        pairs = abbreviation_pairs(t)
        cued_present = [i for i in keep if i["ref"].startswith("cued")]
        if not cued_present and len(pairs) == 1:
            keep.append({"ref": "cued_1", "unit": "none", "cues": list(pairs[0])})
        elif len(cued_present) == 1 and len(pairs) == 1 and cued_present[0]["cues"] != list(pairs[0]):
            # Attempt 3: one cued input and one defined abbreviation in the
            # clause determine its cues uniquely ("polarization index (PI)").
            cued_present[0]["cues"] = list(pairs[0])
        for u in mentioned:
            kind_u = UNIT_KIND[u]
            if kind_u != "cued" and kind_u not in seen and len([m for m in mentioned if UNIT_KIND[m] == kind_u]) == 1:
                keep.append({"ref": kind_u, "unit": u, "cues": []})
                seen.add(kind_u)
        order = {"voltage": 0, "resistance": 1, "temperature": 2, "cued_1": 3, "cued_2": 4}
        keep.sort(key=lambda i: order[i["ref"]])
        if keep != before:
            v.repairs.append({"field": "inputs", "from": before, "to": keep, "basis": "units and abbreviation named in clause"})
            c["inputs"] = keep
            v.issues = [i for i in v.issues if not i["field"].startswith("inputs[")]
        refs = [i["ref"] for i in c["inputs"]]
        if len(set(refs)) != len(refs):
            v.issues.append({"field": "inputs", "issue": "an input is declared twice"})
    elif kind in ("missing_input", "default_outcome"):
        _check_value(v, "outcome", c["outcome"], outcome_match(t, outcomes), lambda x: c.__setitem__("outcome", x))
    elif kind == "validity":
        num_ok("min", c["min"])
        num_ok("max", c["max"])
        m = re.search(r"between\s+(\S+)\s+and\s+(\S+)", t)
        if m:
            vals = [n for n in nums if m.start() <= n.start <= m.end()]
            if len(vals) == 2:
                lo, hi = sorted([vals[0], vals[1]], key=lambda n: n.value)
                _check_value(v, "min", float(c["min"]), [float(lo.value)], lambda x: c.__setitem__("min", x))
                _check_value(v, "max", float(c["max"]), [float(hi.value)], lambda x: c.__setitem__("max", x))
                kinds = sorted({UNIT_KIND[n.unit] for n in vals if n.unit != "none"})
                _check_value(v, "ref", c["ref"], kinds, lambda x: c.__setitem__("ref", x))
                c["unit"] = next((n.unit for n in vals if n.unit != "none"), "none")
        c.setdefault("unit", next((n.unit for n in nums if float(n.value) == float(c["min"]) and n.unit != "none"), "none"))
        cand = outcome_match(t, outcomes)
        nxt = ctx.get("next_text", "")
        if not cand and re.match(r"\s*(?:outside|otherwise|if not)\b", nxt, re.IGNORECASE):
            cand = outcome_match(nxt, outcomes)  # the next sentence refers back to this range
            v.fields["outcome.cited_next_clause"] = "evidence" if cand else "hypothesis"
        _check_value(v, "outcome", c["outcome"], cand, lambda x: c.__setitem__("outcome", x))
        if float(c["min"]) > float(c["max"]):
            v.issues.append({"field": "min/max", "issue": "min > max"})
    elif kind == "correction":
        tmpl = []
        if re.search(r"rais\w* to the power|\bpower of\b", low):
            tmpl.append("multiply_power_per_degree")
        if re.search(r"\badd\w*\b.*\bfor every degree|\bper degree\b", low):
            tmpl.append("add_per_degree")
        _check_value(v, "template", c["template"], tmpl, lambda x: c.__setitem__("template", x))
        temps = [n for n in nums if UNIT_KIND[n.unit] == "temperature"]
        _check_value(v, "reference", float(c["reference"]), sorted({float(n.value) for n in temps}),
                     lambda x: c.__setitem__("reference", x))
        c["reference_unit"] = next((n.unit for n in temps if float(n.value) == float(c["reference"])), "°C")
        _check_value(v, "by", c["by"], ["temperature"], lambda x: c.__setitem__("by", x))
        named = [r for r, p in SUBJECT_WORDS.items() if r != "temperature" and re.search(p, t, re.IGNORECASE)]
        _check_value(v, "target", c["target"], named, lambda x: c.__setitem__("target", x))
        if c["template"] == "add_per_degree":
            rates = [n for n in nums if n.unit != "none" and UNIT_KIND[n.unit] == c["target"]]
            _check_value(v, "rate", float(c["rate"]), sorted({float(n.value) for n in rates}), lambda x: c.__setitem__("rate", x))
            c["rate_unit"] = next((n.unit for n in rates if float(n.value) == float(c["rate"])), "none")
            c["base"], c["step"] = 1, 1
        else:
            for f in ("base", "step"):
                num_ok(f, c[f])
                _set(v, f, "hypothesis")
            c["rate"], c["rate_unit"] = 0, c["reference_unit"]
            m = re.search(r"divided by\s+(\S+)", t)
            if m:
                step = [float(n.value) for n in nums if m.start() <= n.start <= m.end()]
                _check_value(v, "step", float(c["step"]), step, lambda x: c.__setitem__("step", x))
            m = re.search(r"by\s+(\S+)\s+raised", t)
            if m:
                base = [float(n.value) for n in nums if m.start() <= n.start <= m.end()]
                _check_value(v, "base", float(c["base"]), base, lambda x: c.__setitem__("base", x))
    elif kind == "limit":
        num_ok("coefficient", c["coefficient"])
        num_ok("offset", c["offset"], (0,))
        res_units = [u for u in units_mentioned(t) if UNIT_KIND[u] in ("resistance", "voltage")]
        out_units = [u for u in res_units if UNIT_KIND[u] == "resistance"] or res_units
        c["unit"] = out_units[-1] if out_units else "none"
        tm = ["coefficient_times_input_plus_offset"] if re.search(r"\btimes\s*\(.*\bplus\b", t) else \
            (["constant"] if not re.search(r"\btimes\b", t) else [])
        _check_value(v, "template", c["template"], tm, lambda x: c.__setitem__("template", x))
        m = re.search(r"(\S+)\s+times\s*\(", t)
        if m:
            coef = [float(n.value) for n in nums if m.start() <= n.start <= m.end()]
            _check_value(v, "coefficient", float(c["coefficient"]), coef, lambda x: c.__setitem__("coefficient", x))
        m = re.search(r"\bplus\s+(\S+?)\)", t)
        if m:
            off = [float(n.value) for n in nums if m.start() <= n.start <= m.end()]
            _check_value(v, "offset", float(c["offset"]), off, lambda x: c.__setitem__("offset", x))
        if c["template"] == "coefficient_times_input_plus_offset":
            named = [u for u in units_mentioned(t) if UNIT_KIND[u] == "voltage"]
            _check_value(v, "input", c["input"], ["voltage"] if named else [], lambda x: c.__setitem__("input", x))
    elif kind == "decision_rule":
        cmp = comparators(t)
        conds = c["conditions"]
        if cmp and len(cmp) != len(conds):
            # Attempt 3: the clause fixes the number of conditions (one per
            # comparator phrase). Rebuild that many, seeding each from the
            # model's condition with the same operator (else its first);
            # every field is then re-verified below.
            rebuilt = []
            for _, op in cmp:
                src = next((x for x in conds if x["op"] == op), conds[0])
                rebuilt.append(dict(src))
            v.repairs.append({"field": "conditions", "from": conds, "to": "one condition per comparator phrase",
                              "basis": f"clause has {len(cmp)} comparator(s)"})
            c["conditions"] = conds = rebuilt
        if len(cmp) == len(conds):
            m_if = re.search(r"\bif\b", t, re.IGNORECASE)
            seg_start = m_if.end() if m_if else 0
            prev_subject = ctx.get("prev_subject")
            for k, (cond, (pos, op)) in enumerate(zip(conds, cmp)):
                _check_value(v, f"conditions[{k}].op", cond["op"], [op], lambda x, cd=cond: cd.__setitem__("op", x))
                seg = t[seg_start:pos]
                subj = subject_candidates(seg, ctx.get("cues", {}))
                if not subj and k > 0:
                    subj = [conds[k - 1]["subject"]]
                if not subj and re.search(r"\bit\b", seg) and prev_subject:
                    subj = [prev_subject]
                _check_value(v, f"conditions[{k}].subject", cond["subject"], subj, lambda x, cd=cond: cd.__setitem__("subject", x))
                nxt = cmp[k + 1][0] if k + 1 < len(cmp) else len(t)
                after = t[pos:nxt]
                after_nums = [n for n in nums if pos <= n.start < nxt]
                if re.search(LIMIT_WORDS, after, re.IGNORECASE) and not [n for n in after_nums if n.unit != "none" or n.value > 1]:
                    _check_value(v, f"conditions[{k}].against", cond["against"], ["limit"], lambda x, cd=cond: cd.__setitem__("against", x))
                    fr = [float(n.value) for n in after_nums if n.value < 1]
                    _check_value(v, f"conditions[{k}].number", float(cond["number"]), fr or [1.0],
                                 lambda x, cd=cond: cd.__setitem__("number", x))
                else:
                    _check_value(v, f"conditions[{k}].against", cond["against"], ["number"], lambda x, cd=cond: cd.__setitem__("against", x))
                    first = after_nums[:1]
                    _check_value(v, f"conditions[{k}].number", float(cond["number"]), [float(n.value) for n in first],
                                 lambda x, cd=cond: cd.__setitem__("number", x))
                    cond["unit"] = first[0].unit if first else "none"
                seg_start = pos
        else:
            v.issues.append({"field": "conditions", "issue": f"{len(conds)} condition(s) but clause has {len(cmp)} comparator(s)"})
            for k, cond in enumerate(conds):
                num_ok(f"conditions[{k}].number", cond["number"], (1,))
        for cond in conds:
            if cond["against"] == "number" and "unit" not in cond:
                cond["unit"] = next((n.unit for n in nums if float(n.value) == float(cond["number"])), "none")
        tail = t[cmp[-1][0]:] if cmp else t
        _check_value(v, "outcome", c["outcome"], outcome_match(tail.split(",", 1)[-1], outcomes) or outcome_match(t, outcomes),
                     lambda x: c.__setitem__("outcome", x))
    return v


def coverage_issues(clauses: list[Clause], claimed: dict[str, list[str]], outcomes: list[str]) -> list[dict]:
    """Clauses that state numbers or an outcome but were interpreted as 'none'."""
    out = []
    for cl in clauses:
        kinds = claimed.get(cl.cid, [])
        if kinds and kinds != ["none"]:
            continue
        if comparators(cl.text) and (clause_numbers(cl.text) or outcome_match(cl.text, outcomes)):
            out.append({"clause": cl.cid, "issue": "clause states a condition but no claim was made", "text": cl.text})
    return out


# ── 5. assembly into the existing IR + consistency checks ─────────────────────

def _implied(cond: dict, earlier: list[dict]) -> bool:
    """True when every request reaching this rule already satisfies `cond`
    because an earlier single-condition rule caught the complement:
    'x >= a' is implied by an earlier 'x < a'; 'x > a' by an earlier 'x <= a'."""
    comp = {">=": "<", ">": "<="}.get(cond["op"])
    if comp is None:
        return False
    for r in earlier:
        if r["value"] == cond["subject"] and r["op"] == comp and r["against"] == cond["against"] \
                and Fraction(str(r["number"] if r["against"] == "number" else r["limit_fraction"])) == Fraction(str(cond["number"])):
            return True
    return False


def assemble(claims: list[dict]) -> tuple[dict, list[dict], list[dict]]:
    """Build the ir_compiler IR from verified claims, in document order.
    Returns (ir, simplifications, issues). Later claims of single-valued
    kinds conflicting with earlier ones are issues, never silently merged."""
    ir = {"topic_terms": [], "inputs": [], "out_of_scope_terms": [], "out_of_scope_limits": [],
          "missing_input_outcome": None, "validity": [], "correction": None, "limit": None, "rules": [],
          "default_outcome": None}
    simp, issues = [], []
    neg = {"<": ">=", "<=": ">", ">": "<=", ">=": "<"}
    for cl in claims:
        k, c, cid = cl["kind"], cl["claim"], cl["clause"]
        if k == "scope_subject":
            ir["topic_terms"] += [w for w in c["terms"] if w not in ir["topic_terms"]]
        elif k == "scope_exclusion_terms":
            ir["out_of_scope_terms"] += [w for w in c["terms"] if w not in ir["out_of_scope_terms"]]
        elif k == "scope_limit":
            op = c["op"] if c["meaning"] == "out_of_scope_when_true" else neg[c["op"]]
            lim = {"ref": c["ref"], "op": op, "value": c["value"], "unit": c.get("unit", "none")}
            if lim not in ir["out_of_scope_limits"]:
                ir["out_of_scope_limits"].append(lim)
        elif k == "required_inputs":
            if ir["inputs"]:
                issues.append({"clause": cid, "issue": "inputs stated twice"})
            ir["inputs"] = [{"ref": i["ref"], "unit": i["unit"], "cues": i["cues"]} for i in c["inputs"]]
        elif k in ("missing_input", "default_outcome"):
            key = "missing_input_outcome" if k == "missing_input" else "default_outcome"
            if ir[key] not in (None, c["outcome"]):
                issues.append({"clause": cid, "issue": f"{key} stated twice with different outcomes"})
            ir[key] = c["outcome"]
        elif k == "validity":
            ir["validity"].append({"ref": c["ref"], "min": c["min"], "max": c["max"], "unit": c.get("unit", "none"), "outcome": c["outcome"]})
        elif k == "correction":
            if ir["correction"] is not None:
                issues.append({"clause": cid, "issue": "two corrections"})
            ir["correction"] = {"template": c["template"], "target": c["target"], "by": c["by"], "reference": c["reference"],
                                "reference_unit": c.get("reference_unit", "°C"), "rate": c.get("rate", 0),
                                "rate_unit": c.get("rate_unit", "°C"), "base": c.get("base", 1), "step": c.get("step", 1)}
        elif k == "limit":
            if ir["limit"] is not None:
                issues.append({"clause": cid, "issue": "two limits"})
            ir["limit"] = {"template": c["template"], "coefficient": c["coefficient"], "input": c["input"],
                           "offset": c["offset"], "unit": c.get("unit", "none")}
        elif k == "decision_rule":
            conds = [x for x in c["conditions"] if not _implied(x, ir["rules"])]
            for x in c["conditions"]:
                if x not in conds:
                    simp.append({"clause": cid, "dropped_condition": x, "basis": "implied by an earlier rule (precedence)"})
            if len(conds) != 1:
                issues.append({"clause": cid, "issue": f"{len(conds)} independent conditions; the IR has no conjunction"})
                continue
            x = conds[0]
            ir["rules"].append({"value": x["subject"], "op": x["op"], "against": x["against"],
                                "number": x["number"] if x["against"] == "number" else 0,
                                "unit": x.get("unit", "none") if x["against"] == "number" else "none",
                                "limit_fraction": x["number"] if x["against"] == "limit" else 1, "outcome": c["outcome"]})
    if ir["correction"] is None:
        ir["correction"] = {"template": "none", "target": "temperature", "by": "temperature", "reference": 0,
                            "reference_unit": "°C", "rate": 0, "rate_unit": "°C", "base": 1, "step": 1}
    if ir["limit"] is None:
        ir["limit"] = {"template": "none", "coefficient": 0, "input": "temperature", "offset": 0, "unit": "°C"}
    for key in ("missing_input_outcome", "default_outcome"):
        if ir[key] is None:
            issues.append({"clause": None, "issue": f"{key} not stated by any claim"})
    if not ir["inputs"]:
        issues.append({"clause": None, "issue": "no required inputs stated"})
    # Untagged rule thresholds take the unit of the input they compare.
    units = {i["ref"]: i["unit"] for i in ir["inputs"]}
    tgt = ir["correction"]["target"]
    for r in ir["rules"]:
        if r["against"] == "number" and r["unit"] == "none":
            r["unit"] = units.get(tgt if r["value"] == "corrected" else r["value"], "none")
    for lim in ir["out_of_scope_limits"]:
        if lim["unit"] == "none":
            lim["unit"] = units.get(lim["ref"], "none")
    for v in ir["validity"]:
        if v["unit"] == "none":
            v["unit"] = units.get(v["ref"], "none")
    return ir, simp, issues


def consistency(ir: dict, outcomes: list[str], doc_outcomes: list[str]) -> list[dict]:
    """Deterministic checks on the assembled IR (exact rational arithmetic).

    - variable definitions: every referenced input is declared;
    - unit compatibility: thresholds' unit kind equals the compared value's kind;
    - rule precedence: a rule unreachable because an earlier rule on the same
      value catches every value it would catch;
    - contradictions: identical conditions with different outcomes;
    - threshold boundaries: validity min ≤ max;
    - missing-data behaviour stated; every outcome the document names is reachable."""
    out = []
    declared = {i["ref"] for i in ir["inputs"]}
    kind_of = {i["ref"]: UNIT_KIND.get(i["unit"], "cued") for i in ir["inputs"]}
    tgt = ir["correction"]["target"]
    for k, r in enumerate(ir["rules"]):
        ref = tgt if r["value"] == "corrected" else r["value"]
        if r["value"] == "corrected" and ir["correction"]["template"] == "none":
            out.append({"rule": k, "issue": "uses 'corrected' but no correction is defined"})
        elif ref not in declared:
            out.append({"rule": k, "issue": f"{ref} is not a declared input"})
        elif r["against"] == "number" and UNIT_KIND.get(r["unit"], "cued") != kind_of.get(ref):
            out.append({"rule": k, "issue": f"unit {r['unit']} does not match {ref}"})
        if r["against"] == "limit" and ir["limit"]["template"] == "none":
            out.append({"rule": k, "issue": "compares against a limit that is not defined"})
    for k, r in enumerate(ir["rules"]):
        thr = Fraction(str(r["number"] if r["against"] == "number" else r["limit_fraction"]))
        for j in range(k):
            e = ir["rules"][j]
            if (e["value"], e["against"]) != (r["value"], r["against"]):
                continue
            et = Fraction(str(e["number"] if e["against"] == "number" else e["limit_fraction"]))
            if e["op"] == r["op"] and et == thr and e["outcome"] != r["outcome"]:
                out.append({"rule": k, "issue": f"contradicts rule {j}: same condition, different outcome"})
            elif r["op"] in ("<", "<=") and e["op"] in ("<", "<=") and (et > thr or (et == thr and (e["op"] == "<=" or r["op"] == "<"))):
                out.append({"rule": k, "issue": f"unreachable: rule {j} already catches every value it would catch"})
            elif r["op"] in (">", ">=") and e["op"] in (">", ">=") and (et < thr or (et == thr and (e["op"] == ">=" or r["op"] == ">"))):
                out.append({"rule": k, "issue": f"unreachable: rule {j} already catches every value it would catch"})
    for k, v in enumerate(ir["validity"]):
        if Fraction(str(v["min"])) > Fraction(str(v["max"])):
            out.append({"validity": k, "issue": "min > max"})
        if v["ref"] not in declared:
            out.append({"validity": k, "issue": f"{v['ref']} is not a declared input"})
    reach = {ir["missing_input_outcome"], ir["default_outcome"]} | {r["outcome"] for r in ir["rules"]} | \
            {v["outcome"] for v in ir["validity"]}
    if ir["out_of_scope_terms"] or ir["out_of_scope_limits"]:
        reach.add("OUT_OF_SCOPE")
    for o in doc_outcomes:
        if o not in reach:
            out.append({"outcome": o, "issue": "named by the document but unreachable"})
    for o in reach - set(outcomes) - {None}:
        out.append({"outcome": o, "issue": "not an allowed outcome"})
    return out


def doc_outcomes(clauses: list[Clause], outcomes: list[str]) -> list[str]:
    """Outcomes that some clause names uniquely (expected to be reachable)."""
    found = []
    for cl in clauses:
        m = outcome_match(cl.text, outcomes)
        if len(m) == 1 and m[0] not in found:
            found.append(m[0])
    return found


# ── 6. deterministic boundary counterexamples + reference evaluator ───────────

def _canon(value: float, unit: str) -> float:
    from ir_compiler import CONVERT, UNIT_KIND as UK
    return CONVERT[UK[unit][1]](float(value))


def evaluate_ir(ir: dict, x: dict) -> str:
    """Reference semantics of the IR on canonical-unit inputs `x`
    (ref → float or None); mirrors ir_compiler's emitted order:
    numeric scope → missing → validity → rules → default. Text guards are
    not modelled (inputs are numeric)."""
    for lim in ir["out_of_scope_limits"]:
        v = x.get(lim["ref"])
        if v is not None and _cmp(v, lim["op"], _canon(lim["value"], lim["unit"])):
            return "OUT_OF_SCOPE"
    if any(x.get(i["ref"]) is None for i in ir["inputs"]):
        return ir["missing_input_outcome"]
    for v in ir["validity"]:
        lo, hi = _canon(v["min"], v["unit"]), _canon(v["max"], v["unit"])
        if x[v["ref"]] < lo or x[v["ref"]] > hi:
            return v["outcome"]
    vals = dict(x)
    c = ir["correction"]
    if c["template"] == "add_per_degree":
        from ir_compiler import CONVERT, UNIT_KIND as UK
        conv = UK[c["rate_unit"]][1]
        rate = CONVERT["id" if conv == "f_to_c" else conv](float(c["rate"]))  # a rate is a difference: no offset
        vals["corrected"] = x[c["target"]] + rate * (x[c["by"]] - _canon(c["reference"], c["reference_unit"]))
    elif c["template"] == "multiply_power_per_degree":
        vals["corrected"] = x[c["target"]] * float(c["base"]) ** ((x[c["by"]] - _canon(c["reference"], c["reference_unit"])) / float(c["step"]))
    lim = ir["limit"]
    if lim["template"] == "constant":
        vals["limit"] = _canon(lim["coefficient"], lim["unit"])
    elif lim["template"] != "none":
        vals["limit"] = _canon(lim["coefficient"], lim["unit"]) * (x[lim["input"]] + float(lim["offset"]))
    for r in ir["rules"]:
        rhs = float(r["limit_fraction"]) * vals["limit"] if r["against"] == "limit" else _canon(r["number"], r["unit"])
        if _cmp(vals[r["value"]], r["op"], rhs):
            return r["outcome"]
    return ir["default_outcome"]


def _cmp(a: float, op: str, b: float) -> bool:
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]


def boundary_points(ir: dict) -> list[dict]:
    """Deterministic counterexample inputs (canonical units): for every scope
    limit, validity bound and rule threshold, the threshold itself and points
    just inside and outside it, plus one point per missing input. Other inputs
    are held at a neutral point (correction reference temperature; mid
    validity range; values that clear the cued thresholds). No labels."""
    refs = [i["ref"] for i in ir["inputs"]]
    neutral: dict[str, float] = {}
    for v in ir["validity"]:
        neutral[v["ref"]] = (_canon(v["min"], v["unit"]) + _canon(v["max"], v["unit"])) / 2
    c = ir["correction"]
    if c["template"] != "none":
        neutral[c["by"]] = _canon(c["reference"], c["reference_unit"])
    for lim in ir["out_of_scope_limits"]:
        neutral.setdefault(lim["ref"], _canon(lim["value"], lim["unit"]) / 3)
    for r in ir["rules"]:
        if r["against"] == "number" and r["value"] in refs and r["value"] not in neutral:
            ths = [_canon(q["number"], q["unit"]) for q in ir["rules"] if q["value"] == r["value"] and q["against"] == "number"]
            neutral[r["value"]] = max(ths) * 1.5 if all(q["op"] in ("<", "<=") for q in ir["rules"] if q["value"] == r["value"]) \
                else (min(ths) + max(ths)) / 2
    for ref in refs:
        neutral.setdefault(ref, 1.0e6 if ref == "resistance" else 1.0)
    pts: list[dict] = []

    def around(ref: str, thr: float, why: str) -> None:
        eps = abs(thr) * 1e-3 or 1e-3
        for d, tag in ((-eps, "below"), (0.0, "at"), (eps, "above")):
            p = dict(neutral)
            p[ref] = thr + d
            pts.append({"inputs": p, "probe": f"{why} {tag}"})

    for k, lim in enumerate(ir["out_of_scope_limits"]):
        around(lim["ref"], _canon(lim["value"], lim["unit"]), f"scope_limit[{k}]")
    for k, v in enumerate(ir["validity"]):
        around(v["ref"], _canon(v["min"], v["unit"]), f"validity[{k}].min")
        around(v["ref"], _canon(v["max"], v["unit"]), f"validity[{k}].max")
    for k, r in enumerate(ir["rules"]):
        if r["against"] == "number":
            ref = c["target"] if r["value"] == "corrected" else r["value"]
            around(ref, _canon(r["number"], r["unit"]), f"rule[{k}]")
        elif ir["limit"]["template"] != "none":
            lim = ir["limit"]
            base = _canon(lim["coefficient"], lim["unit"]) * ((neutral.get(lim["input"], 0) if lim["template"] != "constant" else 1) + float(lim["offset"]))
            if lim["template"] == "constant":
                base = _canon(lim["coefficient"], lim["unit"])
            ref = c["target"] if r["value"] == "corrected" else r["value"]
            around(ref, float(r["limit_fraction"]) * base, f"rule[{k}]")
    for ref in refs:
        p = dict(neutral)
        p[ref] = None
        pts.append({"inputs": p, "probe": f"missing {ref}"})
    return pts


def render(ir: dict, point: dict, topic: str) -> str:
    """Request text for a canonical-unit point, in units the runtime parser reads."""
    sym = {"voltage": "kV", "resistance": "MΩ", "temperature": "°C"}
    parts = []
    for i in ir["inputs"]:
        v = point[i["ref"]]
        if v is None:
            continue
        lit = repr(float(v)) if v != int(v) else str(int(v))  # round-trip exact (thresholds)
        parts.append(f"{i['cues'][0]} {lit}" if i["ref"].startswith("cued") else f"{lit} {sym[i['ref']]}")
    return f"{topic}: " + ", ".join(parts) + "."


def field_summary(verified: list[dict]) -> dict:
    """Counts of field provenance across all claims."""
    s = {"evidence": 0, "repaired": 0, "hypothesis": 0, "issues": 0}
    for v in verified:
        for st in v["fields"].values():
            s[st] += 1
        s["issues"] += len(v["issues"])
    return s
