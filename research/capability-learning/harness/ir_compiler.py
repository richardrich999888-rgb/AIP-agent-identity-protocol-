"""Constrained capability compiler: typed intermediate representation → capability.

Pure and deterministic. A model fills the IR (see IR_SCHEMA); this module
validates it, converts units, writes every expression, names every variable,
and emits the existing `Capability` artifact, which is then validated by the
unchanged runtime (signed expert suite, approval, lifecycle).

Division of labour (sprint diagnosis): the model's failures were all in
free-text fields — undefined or misspelled names, operator precedence,
outcome/ordering mistakes, unmatchable applicability phrases. Here the model
only chooses enums and numbers; it never writes an expression or a name.

Mechanical repairs (never change meaning): unit spellings added to the
applicability terms for every declared input kind; cue-word case variants.
Not repaired, ever: thresholds, outcomes, rule order, scope or validity
limits — a wrong one fails validation and is reported.

Assumptions and limits (stated, tested):
- at most one input per physical kind (voltage, resistance, temperature);
  up to two cued (dimensionless) inputs;
- one optional correction (none | add_per_degree | multiply_power_per_degree)
  and one optional limit (constant | coefficient × (input + offset));
- canonical units are the runtime parser's: kV, MΩ, °C; °F thresholds are
  converted; cued inputs are unitless.
"""
from __future__ import annotations

from dataclasses import dataclass

KINDS = ("voltage", "resistance", "temperature", "cued")
PHYS_REFS = ("voltage", "resistance", "temperature")
INPUT_REFS = PHYS_REFS + ("cued_1", "cued_2")
VALUE_REFS = INPUT_REFS + ("corrected",)
UNITS = ("kV", "V", "MΩ", "GΩ", "kΩ", "°C", "°F", "none")
OPS = ("<", "<=", ">", ">=")
# unit → (kind, conversion). Conversions use exactly the runtime parser's
# arithmetic (quantity.rs milli = v / 1000, kilo = v * 1000, f_to_c =
# (v - 32) * 5 / 9) so a threshold and a parsed reading written with the same
# decimal literal compare equal at boundaries.
UNIT_KIND = {"kV": ("voltage", "id"), "V": ("voltage", "milli"), "MΩ": ("resistance", "id"),
             "GΩ": ("resistance", "kilo"), "kΩ": ("resistance", "milli"), "°C": ("temperature", "id"),
             "°F": ("temperature", "f_to_c"), "none": ("cued", "id")}
CONVERT = {"id": lambda v: v, "milli": lambda v: v / 1000.0, "kilo": lambda v: v * 1000.0,
           "f_to_c": lambda v: (v - 32.0) * 5.0 / 9.0}
# Spellings the runtime parser recognises (quantity.rs), used as applicability terms.
UNIT_TERMS = {"voltage": ["V", "volt", "volts", "kV"],
              "resistance": ["megohm", "megohms", "MΩ", "Mohm", "GΩ", "kΩ"],
              "temperature": []}  # temperature words are too common to signal applicability
MAX_RULES = 10

REF = {"enum": list(INPUT_REFS)}
VREF = {"enum": list(VALUE_REFS)}
NUM = {"type": "number"}


def ir_schema(outcomes: list[str]) -> dict:
    """JSON schema the model's output is constrained to."""
    out = {"enum": outcomes}
    unit = {"enum": list(UNITS)}
    return {"type": "object", "properties": {
        "topic_terms": {"type": "array", "items": {"type": "string", "maxLength": 32}, "minItems": 1, "maxItems": 8},
        "inputs": {"type": "array", "minItems": 1, "maxItems": 5, "items": {"type": "object", "properties": {
            "ref": REF, "unit": unit, "cues": {"type": "array", "items": {"type": "string", "maxLength": 32}, "maxItems": 4}},
            "required": ["ref", "unit", "cues"]}},
        "out_of_scope_terms": {"type": "array", "items": {"type": "string", "maxLength": 32}, "maxItems": 8},
        "out_of_scope_limits": {"type": "array", "maxItems": 3, "items": {"type": "object", "properties": {
            "ref": REF, "op": {"enum": list(OPS)}, "value": NUM, "unit": unit}, "required": ["ref", "op", "value", "unit"]}},
        "missing_input_outcome": out,
        "validity": {"type": "array", "maxItems": 3, "items": {"type": "object", "properties": {
            "ref": REF, "min": NUM, "max": NUM, "unit": unit, "outcome": out}, "required": ["ref", "min", "max", "unit", "outcome"]}},
        "correction": {"type": "object", "properties": {
            "template": {"enum": ["none", "add_per_degree", "multiply_power_per_degree"]},
            "target": REF, "by": REF, "reference": NUM, "reference_unit": unit,
            "rate": NUM, "rate_unit": unit, "base": NUM, "step": NUM},
            "required": ["template", "target", "by", "reference", "reference_unit", "rate", "rate_unit", "base", "step"]},
        "limit": {"type": "object", "properties": {
            "template": {"enum": ["none", "constant", "coefficient_times_input_plus_offset"]},
            "coefficient": NUM, "input": REF, "offset": NUM, "unit": unit},
            "required": ["template", "coefficient", "input", "offset", "unit"]},
        "rules": {"type": "array", "minItems": 1, "maxItems": MAX_RULES, "items": {"type": "object", "properties": {
            "value": VREF, "op": {"enum": list(OPS)}, "against": {"enum": ["number", "limit"]},
            "number": NUM, "unit": unit, "limit_fraction": NUM, "outcome": out},
            "required": ["value", "op", "against", "number", "unit", "limit_fraction", "outcome"]}},
        "default_outcome": out,
    }, "required": ["topic_terms", "inputs", "out_of_scope_terms", "out_of_scope_limits", "missing_input_outcome",
                    "validity", "correction", "limit", "rules", "default_outcome"]}


class IRError(ValueError):
    """Structural or type error in the IR (reported to the proposer; never auto-fixed)."""


@dataclass(frozen=True)
class Compiled:
    capability: dict
    repairs: list  # mechanical repairs applied (for the record)


def _kind_of_ref(ref: str) -> str:
    return "cued" if ref.startswith("cued") else ref


def _to_canonical(value: float, unit: str, kind: str, what: str) -> float:
    """Convert a document-unit number to the runtime's canonical unit for `kind`."""
    uk, conv = UNIT_KIND[unit]
    if uk != kind:
        raise IRError(f"{what}: unit {unit} is not a {kind} unit")
    return CONVERT[conv](value)


def _num(x: float) -> str:
    """Plain decimal literal (the expression language has no exponent syntax)
    that parses back to exactly the same float (built from repr, which is
    round-trip exact)."""
    from decimal import Decimal

    if x != x or x in (float("inf"), float("-inf")):
        raise IRError("non-finite number")
    s = format(Decimal(repr(float(x))), "f")
    if float(s) != float(x):
        raise IRError(f"cannot represent {x!r} exactly")
    return s if "." in s else s + ".0"


def compile_ir(ir: dict, spec: dict) -> Compiled:
    """Compile a model-filled IR into a capability artifact (dict)."""
    outcomes = spec["outcomes"]
    repairs: list = []
    declared: dict[str, dict] = {}
    for i in ir["inputs"]:
        ref = i["ref"]
        if ref in declared:
            raise IRError(f"input {ref} declared twice")
        kind = _kind_of_ref(ref)
        if UNIT_KIND[i["unit"]][0] != kind:
            raise IRError(f"input {ref}: unit {i['unit']} is not a {kind} unit")
        if kind == "cued" and not [c for c in i["cues"] if c.strip()]:
            raise IRError(f"input {ref} needs at least one cue word")
        declared[ref] = i

    def need(ref: str, what: str) -> None:
        if ref == "corrected":
            if ir["correction"]["template"] == "none":
                raise IRError(f"{what}: 'corrected' used but correction.template is 'none'")
            return
        if ref not in declared:
            raise IRError(f"{what}: {ref} is not a declared input (declared: {', '.join(declared)})")

    for o in [ir["missing_input_outcome"], ir["default_outcome"]] + [r["outcome"] for r in ir["rules"]] + \
             [v["outcome"] for v in ir["validity"]]:
        if o not in outcomes:
            raise IRError(f"unknown outcome {o}")

    name = {ref: ref for ref in declared}  # variable names are the refs themselves
    inputs = [{"name": ref, "kind": _kind_of_ref(ref), "cues": declared[ref]["cues"] if _kind_of_ref(ref) == "cued" else []}
              for ref in declared]
    # Mechanical repair: identifier-style cue words ("specific_gravity") are
    # serialisation artefacts; text never contains underscores, so they are
    # respelled with spaces. Meaning is unchanged.
    for inp in inputs:
        fixed = [c.replace("_", " ").strip() for c in inp["cues"]]
        if fixed != inp["cues"]:
            repairs.append({"kind": "cue_underscore_to_space", "input": inp["name"], "from": inp["cues"], "to": fixed})
            inp["cues"] = fixed
    # Mechanical repair: cue case variants.
    for inp in inputs:
        if inp["cues"]:
            extra = [c.upper() for c in inp["cues"] if c.upper() not in inp["cues"]] + \
                    [c.lower() for c in inp["cues"] if c.lower() not in inp["cues"]]
            if extra:
                repairs.append({"kind": "cue_case_variants", "input": inp["name"], "added": extra})
                inp["cues"] = (inp["cues"] + extra)[:4]

    # Scope.
    text_guards = [{"any_terms": ir["out_of_scope_terms"], "outcome": "OUT_OF_SCOPE"}] if ir["out_of_scope_terms"] else []
    if text_guards and "OUT_OF_SCOPE" not in outcomes:
        raise IRError("out_of_scope_terms given but OUT_OF_SCOPE is not an outcome")
    numeric_guards = []
    for k, lim in enumerate(ir["out_of_scope_limits"]):
        need(lim["ref"], f"out_of_scope_limits[{k}]")
        v = _to_canonical(lim["value"], lim["unit"], _kind_of_ref(lim["ref"]), f"out_of_scope_limits[{k}]")
        numeric_guards.append({"when": f"{name[lim['ref']]} {lim['op']} {_num(v)}", "outcome": "OUT_OF_SCOPE"})

    # Derived values.
    derive = []
    c = ir["correction"]
    t = c["template"]
    if t != "none":
        need(c["target"], "correction.target")
        need(c["by"], "correction.by")
        tk, bk = _kind_of_ref(c["target"]), _kind_of_ref(c["by"])
        ref_val = _to_canonical(c["reference"], c["reference_unit"], bk, "correction.reference")
        if t == "add_per_degree":
            # A rate is a difference: scale-only conversion (never the °F offset).
            if UNIT_KIND[c["rate_unit"]][0] != tk:
                raise IRError(f"correction.rate: unit {c['rate_unit']} is not a {tk} unit")
            rate = CONVERT[{"f_to_c": "id"}.get(UNIT_KIND[c["rate_unit"]][1], UNIT_KIND[c["rate_unit"]][1])](c["rate"])
            if c["reference_unit"] == "°F":
                rate = rate * 9.0 / 5.0  # per °F → per °C
            expr = f"{c['target']} + {_num(rate)} * ({c['by']} - {_num(ref_val)})"
        else:
            if c["base"] <= 0 or c["step"] == 0:
                raise IRError("multiply_power_per_degree needs base > 0 and step != 0")
            step = c["step"] * (5.0 / 9.0 if c["reference_unit"] == "°F" else 1.0)
            expr = f"{c['target']} * {_num(c['base'])} ^ (({c['by']} - {_num(ref_val)}) / {_num(step)})"
        derive.append({"name": "corrected", "expr": expr})
    elif any(r["value"] == "corrected" for r in ir["rules"]):
        # Not repaired: binding 'corrected' to a raw input would hide a missing correction.
        raise IRError("rules use 'corrected' but correction.template is 'none'")
    lim = ir["limit"]
    has_limit = lim["template"] != "none"
    if has_limit:
        if lim["template"] == "constant":
            kind = UNIT_KIND[lim["unit"]][0]
            derive.append({"name": "limit", "expr": _num(_to_canonical(lim["coefficient"], lim["unit"], kind, "limit"))})
        else:
            need(lim["input"], "limit.input")
            # limit = coefficient × (input + offset), result in lim.unit (a resistance or voltage unit).
            out_kind = UNIT_KIND[lim["unit"]][0]
            if out_kind == "temperature":
                raise IRError("limit.unit: a temperature limit cannot be scaled")
            scale = _to_canonical(1.0, lim["unit"], out_kind, "limit.unit")
            derive.append({"name": "limit", "expr": f"{_num(lim['coefficient'] * scale)} * ({lim['input']} + {_num(lim['offset'])})"})

    # Rules: validity first, then the model's rules in order.
    rules = []
    for k, v in enumerate(ir["validity"]):
        need(v["ref"], f"validity[{k}]")
        kind = _kind_of_ref(v["ref"])
        lo = _to_canonical(v["min"], v["unit"], kind, f"validity[{k}]")
        hi = _to_canonical(v["max"], v["unit"], kind, f"validity[{k}]")
        if lo > hi:
            raise IRError(f"validity[{k}]: min > max")
        rules.append({"when": f"{v['ref']} < {_num(lo)} or {v['ref']} > {_num(hi)}", "outcome": v["outcome"]})
    for k, r in enumerate(ir["rules"]):
        need(r["value"], f"rules[{k}]")
        if r["against"] == "limit":
            if not has_limit:
                raise IRError(f"rules[{k}] compares against a limit but no limit is defined")
            rhs = "limit" if r["limit_fraction"] == 1 else f"{_num(r['limit_fraction'])} * limit"
        else:
            kind = _kind_of_ref(c["target"] if r["value"] == "corrected" else r["value"])
            rhs = _num(_to_canonical(r["number"], r["unit"], kind, f"rules[{k}]"))
        rules.append({"when": f"{r['value']} {r['op']} {rhs}", "outcome": r["outcome"]})

    # Applicability: topic terms + cue words + unit spellings (mechanical repair).
    terms = list(dict.fromkeys([x for x in ir["topic_terms"] if x.strip()]))
    added = []
    for inp in inputs:
        for w in UNIT_TERMS.get(inp["kind"], []) + inp["cues"]:
            if w not in terms:
                terms.append(w)
                added.append(w)
    if added:
        repairs.append({"kind": "applicability_unit_and_cue_terms", "added": added})
    cap = {
        "id": spec["capability_id"], "version": 1, "intended_task": spec["intended_task"], "outcomes": outcomes,
        "applicability": {"any_terms": terms[:32], "min_inputs_present": min(2, len(inputs))},
        "procedure": {"inputs": inputs, "text_guards": text_guards, "numeric_guards": numeric_guards,
                      "missing_input_outcome": ir["missing_input_outcome"], "derive": derive,
                      "rules": rules, "default_outcome": ir["default_outcome"]},
        "required": {"tenant": spec["tenant"], "min_clearance": spec["clearance"], "security_domain": spec["domain"]},
        "dependencies": {"knowledge": {spec["doc_id"]: ""}, "policy_version": spec["policy_version"], "execution_model_sha256": None},
        "evidence_refs": [spec["doc_id"]] + spec.get("demo_ids", []),
        "failure_conditions": ["an input appears twice with different values", "a unit the runtime does not recognise"],
        "tests": [],
        "proposed_by": spec["proposed_by"],
    }
    return Compiled(cap, repairs)


# ── Step C: deterministic evidence checks (no repair) ─────────────────────────

NUMBER_WORDS = {"half": 0.5, "one": 1.0, "two": 2.0, "three": 3.0, "four": 4.0, "five": 5.0,
                "ten": 10.0, "twice": 2.0, "double": 2.0}


def document_numbers(doc: str) -> set:
    """Every numeric value stated in the document (literals and number words)."""
    import re

    vals = {float(x) for x in re.findall(r"(?<![\w.])\d+(?:\.\d+)?", doc)}
    vals |= {v for w, v in NUMBER_WORDS.items() if re.search(rf"\b{w}\b", doc, re.IGNORECASE)}
    # v0.2: fraction words stated in the text (exact value of the float the IR carries).
    for w, (a, b) in {"one third": (1, 3), "two thirds": (2, 3), "one quarter": (1, 4)}.items():
        if re.search(rf"\b{w}\b", doc, re.IGNORECASE):
            vals.add(a / b)
    return vals


def used_numbers(ir: dict) -> list:
    """(path, value) of every number the procedure actually depends on."""
    out = [(f"out_of_scope_limits[{k}].value", x["value"]) for k, x in enumerate(ir["out_of_scope_limits"])]
    for k, v in enumerate(ir["validity"]):
        out += [(f"validity[{k}].min", v["min"]), (f"validity[{k}].max", v["max"])]
    c = ir["correction"]
    if c["template"] == "add_per_degree":
        out += [("correction.reference", c["reference"]), ("correction.rate", c["rate"])]
    elif c["template"] == "multiply_power_per_degree":
        out += [("correction.reference", c["reference"]), ("correction.base", c["base"]), ("correction.step", c["step"])]
    lim = ir["limit"]
    if lim["template"] == "constant":
        out.append(("limit.coefficient", lim["coefficient"]))
    elif lim["template"] == "coefficient_times_input_plus_offset":
        out += [("limit.coefficient", lim["coefficient"]), ("limit.offset", lim["offset"])]
    for k, r in enumerate(ir["rules"]):
        out.append((f"rules[{k}].number", r["number"]) if r["against"] == "number" else (f"rules[{k}].limit_fraction", r["limit_fraction"]))
    return out


def provenance_check(ir: dict, doc: str) -> list:
    """Numbers in the IR that the document does not state (offset 0 and
    limit_fraction 1 are the identity and need no source)."""
    stated = document_numbers(doc)
    bad = []
    for path, v in used_numbers(ir):
        if (path.endswith(".offset") and v == 0) or (path.endswith("limit_fraction") and v == 1):
            continue
        if float(v) not in stated:
            bad.append({"field": path, "value": v})
    return bad


def triage(ir: dict, spec: dict, doc: str, demo_agreement: int | None, demos: int) -> dict:
    """Step E: CANDIDATE_FOR_EXPERT_VALIDATION only when the IR compiles, every
    number has document provenance and every demonstration agrees; otherwise
    NEEDS_EXPERT_CORRECTION with the reasons. Nothing is repaired here."""
    reasons = []
    try:
        compile_ir(ir, spec)
    except (IRError, KeyError) as e:
        reasons.append(f"does not compile: {e}")
    unsupported = provenance_check(ir, doc)
    if unsupported:
        reasons.append(f"{len(unsupported)} number(s) not stated in the document: {unsupported}")
    if demo_agreement is not None and demo_agreement < demos:
        reasons.append(f"disagrees with {demos - demo_agreement}/{demos} expert demonstrations")
    return {"status": "NEEDS_EXPERT_CORRECTION" if reasons else "CANDIDATE_FOR_EXPERT_VALIDATION", "reasons": reasons,
            "unsupported_numbers": unsupported}
