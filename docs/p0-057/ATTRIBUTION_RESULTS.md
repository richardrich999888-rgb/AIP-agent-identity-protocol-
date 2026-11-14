# Attribution results — executable consistency checkpoint

Source `5be83a87bec680d26510c2be93e66fdfda008b1e`; exact tree
`fe4a962a670c092e9729817272e9513d87dffd46`.

| Executed case | Baseline | Corrected source |
|---|---|---|
| Real `/bin/sh` → `/bin/sleep` exec between metadata and hashing; cold cache | Returns old path with new hash; regression fails | Explicit unavailable snapshot, cache invalidated, new stable image measurable |
| Same controlled exec; warm cache | Returns stale image; regression fails | Explicit unavailable snapshot, cache invalidated, new stable image measurable |
| Open file, consume prefix, replace pathname, hash opened descriptor | New regression | Complete original descriptor bytes hashed from offset zero; replacement pathname hashes differently |
| Stable self measurement/cache and changed fingerprint | Existing regression extended | Stable result/cache retained; start/device/inode/size/mtime/ctime/path mismatches rejected |
| Existing lifecycle/socket/placement/blind-spot suites and observer library | Historical baseline retained | 102 executed passes, zero failures/ignored; no emitted SKIP/UNAVAILABLE early-return diagnostic |

The scheduling hook coordinates real child `exec` at the vulnerable read
boundary; it does not fabricate a kernel event. Final tests retain a live pidfd
across exec. Both samples keep the same boot/PID/start identity and different
image hashes. Signed sample batches contain actual process measurements and
no connector events. No health/coverage certificate is invented for them.

Two signed originals pass the separate native CLI. One-byte changes and wrong
anchors reject; requesting absent health fails explicitly: eight checks total.
These checks cover integrity and refusal behavior, not administrative independence.

Original reproduction patch/log, initial failure, fixed runs, source hashes,
binary hash and signed samples are under
[`iteration-002`](../../validation/p0_057/iteration-002).
They are non-AI synthetic processes, so they provide no AI-discovery precision,
recall or customer-acceptance result. Broader logical-agent attribution is open.
