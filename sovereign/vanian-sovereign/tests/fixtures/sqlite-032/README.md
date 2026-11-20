# Pre-upgrade corpus fixture

`corpus.hex` contains exact checkpointed SQLite database bytes from the public
`SqliteCorpus` adapter at commit `7de9ba4d0fb8da83ec294380e719b82ecadee7ca`, built
with rusqlite **0.32.1**, libsqlite3-sys **0.30.1**, SQLite **3.46.0**. The expected
hash, per-principal search results and dependency digests are in `expected.json`.
All content is synthetic. There are two tenants, three clearances, a quarantined
document and a document replaced once before recording.

The integration test decodes and hashes these bytes, opens them with the updated
engine, and checks access rules, citations' document content, digests, FTS updates,
version increments and persistence after reopening. It does not regenerate the
fixture using the new engine. This is not a malicious-WAL exploit reproduction.

To reproduce in a disposable old-source worktree (directories must be absent):

```bash
git worktree add --detach /tmp/p0-049-sqlite-baseline 7de9ba4d0fb8da83ec294380e719b82ecadee7ca
mkdir -p /tmp/p0-049-sqlite-baseline/sovereign/vanian-sovereign/examples
cp sovereign/vanian-sovereign/tests/fixtures/sqlite-032/generate.rs \
  /tmp/p0-049-sqlite-baseline/sovereign/vanian-sovereign/examples/p0049_legacy_corpus.rs
cd /tmp/p0-049-sqlite-baseline
cargo run --locked -p vanian-sovereign --example p0049_legacy_corpus -- /tmp/p0-049-sqlite-fixture
```

Building may download dependencies unless already staged; this is a developer
fixture command, not the offline installer. The only added baseline source is the
generator. It asserts the linked old engine version and closes the last connection
before encoding the database. No model, network service or signing key is used.
