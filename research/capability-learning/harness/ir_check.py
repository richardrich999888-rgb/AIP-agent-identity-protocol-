"""Does an IR compile? Asked the same way by A3a (draft) and B2 (answered).

Two checks, in order, both reused rather than reimplemented:

1. **The compiler's own schema** (`ir_compiler.ir_schema`), checked strictly
   by `schema_subset`. `compile_ir` does not enforce the schema's `minItems`,
   so without this an IR with no rules and no inputs "compiles".
2. **`compile_ir` itself**, given a complete spec. `compile_ir` reads
   `spec["proposed_by"]` only after validating the whole IR; called with the
   bare task spec it raises `KeyError('proposed_by')` for every IR, and a
   caller that catches `KeyError` records a spec problem as an IR problem.
   That is what A3a's first recordings did.

The capability built here is discarded: this module answers "does it
compile", not "what was proposed". `CHECK_PROPOSER` therefore names no person,
so nothing produced here can be mistaken for an authored artifact; the code
that emits a capability sets the real proposer, and the runtime's separation
of duties (`lifecycle.rs`: approver != proposer) binds to that.
"""

from __future__ import annotations

import schema_subset as S
from ir_compiler import IRError, compile_ir, ir_schema

#: Proposer used only to let `compile_ir` finish. Never emitted.
CHECK_PROPOSER = "check-only:not-emitted"

NOT_ATTEMPTED = "not attempted: the IR does not match the compiler's schema"


def check_ir(ir: dict, spec: dict) -> dict:
    """{schema_errors, compiles, compile_error} for `ir` under `spec`. Pure."""
    schema_errors = S.validate(ir, ir_schema(list(spec["outcomes"])), "ir")
    if schema_errors:
        return {"schema_errors": schema_errors, "compiles": False, "compile_error": NOT_ATTEMPTED}
    try:
        compile_ir(ir, {**spec, "proposed_by": CHECK_PROPOSER, "demo_ids": []})
    except IRError as e:
        return {"schema_errors": [], "compiles": False, "compile_error": str(e)}
    return {"schema_errors": [], "compiles": True, "compile_error": None}
