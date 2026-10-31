# Extraction head (iteration 2)

Architecture: frozen BAAI/bge-small-en-v1.5 sentence encoder (ONNX via
fastembed 0.9.1, 33M parameters, 384-d) → multinomial logistic regression over
the 8 policy quantities → deterministic value picker (`methods/extractors.py:
pick_value`) → deterministic equipment-registry gate → exact SOP policy.
Abstains when top probability < 0.5 (fixed before evaluation), when no value
is found, or when the gate fires. Trained on v2 train (1,200 template texts) in
~52 s on 2 vCPU; no fine-tuning of the encoder.

Held-out result and comparisons: REPORT_ITER2.md. In one line: 0.821 decision
accuracy, 4 wrong releases of 39, p95 57 ms, 755 MB — statistically
indistinguishable in accuracy from TF-IDF (0.795, 0.9 ms, 158 MB) and from
Qwen2.5-1.5B extraction + gate (0.692, 6.1 s, 1.8 GB) at n = 39, but with 3×
fewer wrong releases than the LLM.

Not a new model: an off-the-shelf encoder with a linear head. Prior art for
general-purpose compact extraction: GLiNER (arXiv 2311.08526). Not compared
(not run on this host).
