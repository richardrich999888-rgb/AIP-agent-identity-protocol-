# Demo models (W0.3)

```sh
python3 demos/models/stage.py BUNDLE_DIR --llama-server path/to/llama-server
export SYNTRIASS_BUNDLE=BUNDLE_DIR
python3 deploy/syntriass/resolve_model.py path qwen2.5-1.5b-q4 --verify
```

Model weights never go into git. A demo loads a model only from
`$SYNTRIASS_BUNDLE/models`, after its SHA-256 is checked. No model API is
ever called; these are file downloads, made once on a connected machine.

## What is staged (read 2026-11-08, `PROVENANCE-2026-11-08.json`)

| Logical name | File | Repository @ revision | SHA-256 | Licence |
|---|---|---|---|---|
| `qwen2.5-1.5b-q4` | qwen2.5-1.5b-instruct-q4_k_m.gguf | Qwen/Qwen2.5-1.5B-Instruct-GGUF @ `91cad511` | `6a1a2eb6…` (= manifest) | Apache-2.0 (card, and the repository's LICENSE file) |
| `qwen2.5-1.5b-q8` | qwen2.5-1.5b-instruct-q8_0.gguf | same | `d7efb072…` (= manifest) | same |
| `granite-3.3-2b-q4` | granite-3.3-2b-instruct-Q4_K_M.gguf | ibm-granite/granite-3.3-2b-instruct-GGUF @ `7cdf86cc` | `ac71e9e3…` | Apache-2.0 (card; the repository has no separate LICENSE file) |

Granite is the non-Chinese open option. It is pinned in `extra-models.json`
because `deploy/syntriass/models.manifest.json` belongs to the teaching-demo
session and is not edited here. That entry is the record to add to the
manifest, together with this licence evidence, which lets its
`UNVERIFIED_NO_NETWORK` provenance fields for the two Qwen 1.5B files be
filled in.

**Not staged:** a 7B-class model and Mistral-7B-Instruct. They need more disk
than this sandbox has (about 4–8 GB each).

## llama-server

Built from the same llama.cpp source the benchmark used: the `vendor/llama.cpp`
of the llama-cpp-python 0.3.16 sdist (sha256 `34ed0f9b…`, identical on PyPI),
`cmake -DCMAKE_BUILD_TYPE=Release -DGGML_NATIVE=ON -DLLAMA_CURL=OFF`, which
reports itself as `4227c9b`. Its sha256 is in the provenance file. A native
build depends on the CPU: this one has AVX-512 and AMX.

## Network the staging needed

`huggingface.co` (API and model cards) and `us.aws.cdn.hf.co` (the file
downloads redirect there). The second host was added to this environment's
allowlist on 2026-11-08 for this purpose.
