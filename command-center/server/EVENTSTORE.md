# Event store (item 2.1a)

`eventstore.py` is a stdlib-only, append-only SQLite store. Its properties
are listed in its module docstring, and each one is tested in
`test_eventstore.py`.

- Tests: `python3 -m unittest -v test_eventstore` gives 22 passed / 0 failed /
  0 skipped. That includes adversarial #13 (restart, with a second OS
  process) and #14 (duplicates).
- Mutations: `mutations.txt` records five edits, all caught.

This directory was created before P0-059's `command-center/` lands (item
0.1 is blocked). Only these files are new; they must not collide with
P0-059 files when it is cherry-picked. Ingesting P0-059 run records, and
the inventory, last-seen and risk queries over them, are item **2.1b**.

Known limit: the hash chain cannot reveal deletion of the newest rows
unless a reader holds an earlier `head()`. A test pins this limit
(`test_truncated_tail_needs_a_held_head`). Anchoring the head, for example
in the signed evidence bundle (6.2), closes it.
