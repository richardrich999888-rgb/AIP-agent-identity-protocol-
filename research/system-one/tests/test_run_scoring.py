"""Regression: readouts are scored on the emitted token, not on logprobs.

Iteration-1 finding: the pinned llama.cpp build returned top_logprobs that
disagreed with its own emitted token across sequential requests (emitted 15/16
correct vs logprob argmax 4/16). These tests pin the corrected harness
behaviour with a fake server whose logprobs point at the wrong label.
"""
import json
import types

import numpy as np

from harness import run
from methods import llm


def fake_readout(endpoint, text, cache=True, version="v2"):
    # Logprobs favour label 1; the server actually emitted "4".
    return np.array([-0.01, -9.0, -9.0, -9.0]), 0.001, 1, 1.0, "4"


def test_readout_scores_emitted_token_and_reports_instrument_disagreement(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    for split in run.TEST_SPLITS:
        (data / f"{split}.jsonl").write_text(json.dumps({"id": f"{split}-0", "label": 4, "text": "x", "readings": []}) + "\n")
    monkeypatch.setattr(llm, "readout", fake_readout)
    a = types.SimpleNamespace(data=str(data), out=str(tmp_path), endpoint="127.0.0.1:1", no_cache=False, readout_version="v2", limit=0)
    meta = {}
    run.run_readout(a, meta)
    row = json.loads((tmp_path / "preds_test_id.jsonl").read_text())
    assert row["pred"] == 4, "must score the emitted token, not the logprob argmax"
    assert row["extra"]["emitted"] == "4"
    assert meta["instrument_logprob_argmax_equals_emitted"] == 0.0


def test_unparseable_emission_abstains(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    for split in run.TEST_SPLITS:
        (data / f"{split}.jsonl").write_text(json.dumps({"id": f"{split}-0", "label": 2, "text": "x", "readings": []}) + "\n")
    monkeypatch.setattr(llm, "readout", lambda *a, **k: (np.zeros(4), 0.0, 1, 0.0, "Z"))
    a = types.SimpleNamespace(data=str(data), out=str(tmp_path), endpoint="127.0.0.1:1", no_cache=False, readout_version="v2", limit=0)
    run.run_readout(a, {})
    row = json.loads((tmp_path / "preds_test_id.jsonl").read_text())
    assert np.allclose(row["probs"], 0.25)
