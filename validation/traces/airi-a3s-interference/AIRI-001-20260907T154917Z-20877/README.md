# Cross-check run: A3S Observer attached while this experiment ran

Not part of the canonical 18-run set. One AIRI-001 run performed with the A3S
Observer collector attached, to test whether the tracepoint-interference
finding in `../../external/a3s_observer/TRACEPOINT_INTERFERENCE.md` affects
this experiment's observers.

Artefacts: `a3s_observer.ndjson` (A3S's own event stream) and
`a3s_observer.log` (its attach and shutdown summary) alongside the usual
audit, ftrace, subject and analysis files.
