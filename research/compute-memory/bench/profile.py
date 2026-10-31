"""Compute/memory experiments on llama-server (CPU host). Run inside offline.sh.

usage: profile.py EXPERIMENT OUT_JSON --server BIN --model GGUF [--draft GGUF] [--reps N]
  load      E1 cold vs warm, mmap vs no-mmap: load time, page faults, RSS split
  throughput E2 prefill and decode rates vs prompt length
  prefix    E3 shared-prefix reuse: evaluated tokens and latency, cache on vs off
  sidechan  E3b cross-tenant timing probe, unprotected vs scoped (cachescope)
  restore   E4 slot save/restore vs recompute (hypothesis B4)
  shared    E5 two resident servers on one GGUF: RSS vs PSS (hypothesis B2)
  specdec   E6 speculative decoding with a draft model: equality + decode rate
  builds    E0 two llama-server builds on one model: output equality + rates

Prompts are deterministic (seeded word sampler; seed recorded). Greedy decoding.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
import llama_proc as L  # noqa: E402
from cachescope import CacheScope, SlotTable, decide  # noqa: E402

SEED = 20261031
CTX = 4096
WORDS = ("pump bearing vibration temperature pressure valve inspection shift report operator maintenance "
         "procedure threshold alarm reading sensor calibration schedule plant unit cooling water flow motor "
         "current voltage generator transformer oil level seal leak replace check record supervisor approve "
         "deviation limit normal high low trend weekly daily corrective preventive spare part order").split()


def text(n_words: int, seed: int) -> str:
    """Deterministic pseudo-report text."""
    r = random.Random(seed)
    return " ".join(r.choice(WORDS) for _ in range(n_words))


def text_tokens(srv: L.Server, n_tokens: int, seed: int) -> str:
    """Text whose tokenization is exactly n_tokens (trim word by word)."""
    words = text(int(n_tokens * 1.3) + 20, seed).split()
    lo, hi = 1, len(words)
    while lo < hi:  # largest prefix with <= n_tokens tokens
        mid = (lo + hi + 1) // 2
        if srv.tokens(" ".join(words[:mid])) <= n_tokens:
            lo = mid
        else:
            hi = mid - 1
    return " ".join(words[:lo])


def env(a) -> dict:
    import hashlib
    h = hashlib.sha256()
    with open(a.model, "rb") as f:
        while b := f.read(1 << 22):
            h.update(b)
    return {"model": os.path.basename(a.model), "model_sha256": h.hexdigest(), "host": platform.node(),
            "cpus": os.cpu_count(), "kernel": platform.release(), "seed": SEED, "ctx": CTX,
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def srv(a, port=8190, extra=(), model=None, log=None) -> L.Server:
    return L.Server(a.server, model or a.model, port, ("-c", str(CTX), *a.llama_arg, *extra), log or a.out + ".llama.log")


def exp_load(a) -> dict:
    rows = []
    for rep in range(a.reps):
        for mmap in (True, False):
            for cold in (True, False):
                if cold:
                    L.evict_page_cache(a.model)
                else:
                    open(a.model, "rb").read()  # ensure fully cached
                before = L.cached_fraction(a.model)
                s = srv(a, extra=() if mmap else ("--no-mmap",))
                load = s.start()
                after_load = s.stats()
                r = s.complete(text(200, SEED), 16, cache_prompt=False)
                after_req = s.stats()
                s.stop()
                rows.append({"rep": rep, "mmap": mmap, "cold": cold, "cached_before": round(before, 3), "load_s": round(load, 3),
                             "after_load": after_load, "after_first_request": after_req, "first_request_wall_s": round(r["wall_s"], 3)})
    return {"rows": rows}


def exp_throughput(a) -> dict:
    s = srv(a)
    s.start()
    rows = []
    for n_prompt, n_gen in ((128, 64), (512, 64), (1536, 64), (128, 256)):
        p = text_tokens(s, n_prompt, SEED + n_prompt)
        s.complete(p, 4, cache_prompt=False)  # warm-up
        for rep in range(a.reps):
            r = s.complete(p, n_gen, cache_prompt=False)
            rows.append({"n_prompt": r["prompt_n"], "n_gen": r["predicted_n"], "rep": rep,
                         "prefill_tok_s": r["prompt_n"] / (r["prompt_ms"] / 1000),
                         "decode_tok_s": r["predicted_n"] / (r["predicted_ms"] / 1000),
                         "prompt_ms": r["prompt_ms"], "predicted_ms": r["predicted_ms"], "wall_s": r["wall_s"]})
    st = s.stats()
    s.stop()
    return {"rows": rows, "server_after": st}


def exp_prefix(a) -> dict:
    s = srv(a)
    s.start()
    prefix = text_tokens(s, 1200, SEED)
    sufs = [text(30, SEED + 100 + i) for i in range(a.reps * 4)]
    out = {}
    for cache in (False, True):
        s.complete("reset " + text(20, 1), 1, cache_prompt=False)
        rows = [s.complete(prefix + "\nQuestion: " + q + "\nAnswer:", 8, cache_prompt=cache) for q in sufs]
        out["cache_on" if cache else "cache_off"] = [{k: r[k] for k in ("prompt_n", "prompt_ms", "wall_s", "tokens_cached")} for r in rows]
    s.stop()
    return out


def auc(pos: list[float], neg: list[float]) -> float:
    """P(score_pos > score_neg) (Mann-Whitney U / n1 n2); 0.5 = indistinguishable."""
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def exp_sidechan(a) -> dict:
    """Attacker probes whether the victim's confidential prefix is resident.

    Signal: attacker latency when its guess equals the victim's prefix (hit)
    vs a different prefix of identical length (miss). Score for AUC is
    -latency (faster ⇒ predicted 'victim prefix present').
    """
    # llama-server refuses every /slots action (incl. erase) without a save path.
    d = os.path.join(os.path.dirname(os.path.abspath(a.out)), "slots_sidechan")
    os.makedirs(d, exist_ok=True)
    s = srv(a, extra=("--slot-save-path", d + "/"))
    s.start()
    secret = text_tokens(s, 800, SEED + 7)
    decoy = text_tokens(s, 800, SEED + 8)
    victim = CacheScope("m", "t", "p1", "snap1", "finance:payroll", "restricted")
    attacker = CacheScope("m", "t", "p1", "snap1", "ops:plant-a", "restricted")
    res = {}
    for mode in ("unprotected", "scoped"):
        table = SlotTable(1)

        def send(scope, prompt):
            if mode == "scoped":
                d = decide(table, scope)
                if d.erase_first:
                    s.slot_action(d.slot, "erase")
                return s.complete(prompt, 1, cache_prompt=True, slot=d.slot)
            return s.complete(prompt, 1, cache_prompt=True, slot=0)

        hit, miss, victim_reuse = [], [], []
        for i in range(a.reps * 10):
            send(victim, secret + "\nQ: payroll total for October?")
            guess = secret if i % 2 == 0 else decoy
            r = send(attacker, guess + "\nQ: what is cached?")
            (hit if i % 2 == 0 else miss).append(r["wall_s"])
            v2 = send(victim, secret + "\nQ: payroll total for November?")
            victim_reuse.append(v2["prompt_n"])
            if mode == "scoped" and i == 0:
                assert os.listdir(d) == [], "erase must not write slot files"
        res[mode] = {"hit_wall_s": hit, "miss_wall_s": miss,
                     "auc_attacker": auc([-x for x in hit], [-x for x in miss]),
                     "median_hit_s": statistics.median(hit), "median_miss_s": statistics.median(miss),
                     "victim_second_request_prompt_n": victim_reuse}
    s.stop()
    return res


def exp_restore(a) -> dict:
    d = os.path.join(os.path.dirname(os.path.abspath(a.out)), "slots_tmp")
    os.makedirs(d, exist_ok=True)
    s = srv(a, extra=("--slot-save-path", d + "/"))
    s.start()
    rows = []
    for n in (512, 1536, 3000):
        p = text_tokens(s, n, SEED + n)
        for rep in range(a.reps):
            s.slot_action(0, "erase")
            fill = s.complete(p, 1, cache_prompt=True, slot=0)
            sv, sv_s = s.slot_action(0, "save", f"ckpt_{n}.bin")
            size = os.path.getsize(os.path.join(d, f"ckpt_{n}.bin"))
            s.slot_action(0, "erase")
            rs, rs_s = s.slot_action(0, "restore", f"ckpt_{n}.bin")
            after = s.complete(p + " next", 1, cache_prompt=True, slot=0)
            s.slot_action(0, "erase")
            recompute = s.complete(p + " next", 1, cache_prompt=True, slot=0)
            rows.append({"n_tokens": fill["prompt_n"], "rep": rep, "prefill_ms": fill["prompt_ms"],
                         "save_wall_s": sv_s, "restore_wall_s": rs_s, "file_bytes": size,
                         "after_restore_prompt_n": after["prompt_n"], "after_restore_wall_s": after["wall_s"],
                         "recompute_prompt_n": recompute["prompt_n"], "recompute_wall_s": recompute["wall_s"],
                         "save_resp": sv, "restore_resp": rs})
    s.stop()
    for f in os.listdir(d):
        os.remove(os.path.join(d, f))  # KV checkpoints contain prompt-derived state: never keep them
    os.rmdir(d)
    return {"rows": rows}


def exp_shared(a) -> dict:
    open(a.model, "rb").read()
    one = srv(a, 8191, log=a.out + ".a.log")
    one.start()
    one.complete(text(100, 1), 4, cache_prompt=False)
    solo = one.stats()
    two = srv(a, 8192, log=a.out + ".b.log")
    two.start()
    two.complete(text(100, 2), 4, cache_prompt=False)
    both = {"a": one.stats(), "b": two.stats()}
    two.stop()
    one.stop()
    return {"solo": solo, "pair": both}


def exp_specdec(a) -> dict:
    out = {}
    prompts = [text(60, SEED + i) + "\nWrite a maintenance summary:" for i in range(a.reps)]
    for mode, extra in (("baseline", ()), ("draft", ("-md", a.draft, "--draft-max", "8", "--draft-min", "1"))):
        s = srv(a, extra=extra)
        load = s.start()
        s.complete("warm", 4, cache_prompt=False)
        # llama-server only speculates when cache_prompt is true (server.cpp
        # can_speculate); both modes use it so they differ only in the draft.
        rows = [s.complete(p, 128, cache_prompt=True) for p in prompts]
        st = s.stats()
        s.stop()
        if mode == "draft" and not all(r["draft_n"] for r in rows):
            raise RuntimeError("draft mode ran without speculation; result would be invalid")
        out[mode] = {"load_s": load, "rows": rows, "server": st}
    out["outputs_identical"] = [x["content"] == y["content"] for x, y in zip(out["baseline"]["rows"], out["draft"]["rows"])]
    return out


def exp_builds(a) -> dict:
    """Same model, two llama-server builds: greedy outputs must be identical."""
    out = {}
    prompts = [text(300, SEED + i) + "\nSummarise the shift report:" for i in range(a.reps * 2)]
    for tag, binary in (("baseline", a.server), ("candidate", a.server2)):
        s = L.Server(binary, a.model, 8190, ("-c", str(CTX)), a.out + f".{tag}.llama.log")
        load = s.start()
        s.complete("warm", 4, cache_prompt=False)
        rows = [s.complete(p, 64, cache_prompt=False) for p in prompts]
        st = s.stats()
        s.stop()
        out[tag] = {"binary": binary, "load_s": load, "server": st, "rows": rows,
                    "prefill_tok_s": statistics.median(r["prompt_n"] / (r["prompt_ms"] / 1000) for r in rows),
                    "decode_tok_s": statistics.median(r["predicted_n"] / (r["predicted_ms"] / 1000) for r in rows)}
    out["outputs_identical"] = [x["content"] == y["content"] for x, y in zip(out["baseline"]["rows"], out["candidate"]["rows"])]
    return out


EXPS = {"builds": exp_builds, "load": exp_load, "throughput": exp_throughput, "prefix": exp_prefix, "sidechan": exp_sidechan,
        "restore": exp_restore, "shared": exp_shared, "specdec": exp_specdec}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("experiment", choices=sorted(EXPS))
    ap.add_argument("out")
    ap.add_argument("--server", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--draft")
    ap.add_argument("--llama-arg", action="append", default=[], help="extra llama-server flag (repeatable)")
    ap.add_argument("--server2", help="second llama-server build (experiment 'builds')")
    ap.add_argument("--reps", type=int, default=3)
    a = ap.parse_args()
    if a.experiment == "specdec" and not a.draft:
        ap.error("specdec needs --draft")
    if a.experiment == "builds" and not a.server2:
        ap.error("builds needs --server2")
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    r = {"experiment": a.experiment, "env": {**env(a), "server": a.server, "llama_args": a.llama_arg},
         "result": EXPS[a.experiment](a)}
    json.dump(r, open(a.out, "w"), indent=1)
    print(a.experiment, "done", a.out)


if __name__ == "__main__":
    main()
