# Independent verification instructions

Nothing in this directory asks you to trust a report. Every claim below names
the command that reproduces it and the artifact that holds the bytes.

## 0. What you are verifying, and what you are not

This package records **one executed acceptance run** (which failed, legibly)
and **five framework verifications** (API, revision and licence). It records
**no agent execution**. If you are looking for evidence that smolagents,
aider, goose, browser-use or Open Interpreter ran under Sniffer Dog
observation, it is not here, and `EXECUTION_RESULTS.json` says so in those
words.

## 1. The branch and the reconciliation

```sh
git fetch origin claude/real-agent-acceptance-n5ysvd
git log --oneline origin/claude/real-agent-acceptance-n5ysvd -4
```

Confirm the merge direction independently — PR #8's head must be an ancestor
of this branch, and must NOT have been an ancestor of PR #12's head:

```sh
git merge-base --is-ancestor \
  origin/integration/snifferdog-complete-enterprise-validation \
  origin/claude/real-agent-acceptance-n5ysvd && echo "contained now"

git merge-base --is-ancestor \
  origin/integration/snifferdog-complete-enterprise-validation \
  origin/fix/vanian-end-to-end-green || echo "was NOT contained in PR #12"
```

The four commits that were missing:

```sh
git log --oneline \
  origin/fix/vanian-end-to-end-green..origin/integration/snifferdog-complete-enterprise-validation
```

## 2. The executed acceptance run and its failure

The run is public and its logs are retained by GitHub:

- run 40825279520, job 123286786032, commit `35f215d`, ubuntu-24.04
- https://github.com/richardrich999888-rgb/AIP-agent-identity-protocol-/actions/runs/40825279520

The failing line, verbatim from the job log:

```
File ".../validation/enterprise/same_run_validation.py", line 653, in main
  command(clients,timeout=120,env={**os.environ,'PYTHONPATH':str(ROOT/'sdk/python')})
File ".../integrations/real_agents/evidence.py", line 39, in command
  raise Refused(f"{Path(str(args[0])).name} exited {result.returncode}")
evidence.Refused: python exited 1
```

The run's own evidence is artifact `12876193962` — 43 files, 127,257 bytes,
zip SHA-256 `a9bc42e01e2514c0c15a36b6ec20f42c4798ca2f097b8cdaebdc78bb2ba32455`.
Download it and hash it yourself; do not take the digest from this file.

**Verify the comparison to the earlier failure yourself** rather than
accepting the claim that the reconciliation helped:

```sh
# previously recorded: failed BEFORE the agent, at gateway provisioning
python3 -c "import json;d=json.load(open('validation/enterprise/results/E2E_40753922392/summary.json'));print(d['status'],d['autonomous_workload_executed'])"
```

That prints `FAILED_GATEWAY_ACCOUNT_PROVISIONING_BEFORE_AGENT False`. Run
40825279520 failed at line 653, which is after the agent, the authority, the
MCP call, the kernel observation and the reconciliation. The inference that
the `gateway_password` fix took effect rests on exactly that ordering and
nothing more.

## 3. The repair is insert-only

The claim is that no predicate was removed or softened. Check it without
reading the diff:

```sh
count() { git show "$1:validation/enterprise/run_client_smoke.py" \
  | grep -cE '^\s*assert |\.is_error'; }
count 35f215d    # before the repair
count HEAD       # after
```

Both print `25`. The regression test asserts the same equality against git
history rather than against a threshold:

```sh
python3 -B validation/enterprise/test_client_smoke_diagnostics.py   # 13 tests
python3 -B integrations/real_agents/tests/test_frameworks.py        # 14 tests
python3 -B validation/enterprise/same_run_controls_test.py          # 10 tests
```

The decisive diagnostics property — that an exception message is never
retained — is pinned by
`ClassificationNotEcho.test_the_exception_message_is_never_retained`, which
puts a credential-shaped string in an exception and asserts it appears
nowhere in the written record.

## 4. The five framework verifications

Every API fact in `FRAMEWORK_MATRIX.csv` came from signature inspection of an
installed wheel, not from documentation. Reproduce any row:

```sh
uv venv --python 3.11 v && uv pip install --python v/bin/python 'smolagents==1.26.0'
v/bin/python -c "import inspect
from smolagents import CodeAgent, OpenAIServerModel
print(list(inspect.signature(CodeAgent.__init__).parameters))
print(inspect.signature(CodeAgent.run))
print(list(inspect.signature(OpenAIServerModel.__init__).parameters))"
```

```sh
uv venv --python 3.12 a && uv pip install --python a/bin/python 'aider-chat==0.86.2'
a/bin/aider --help | grep -E '^\s+(--message|--yes-always|--auto-test|--openai-api-base)'
```

```sh
uv venv --python 3.11 b && uv pip install --python b/bin/python 'browser-use==0.13.14'
b/bin/python -c "import inspect
from browser_use import Agent, Browser, ChatOpenAI
print('base_url' in inspect.signature(ChatOpenAI.__init__).parameters)
print(inspect.signature(Agent.run))"
```

**Reproduce the open-interpreter defect**, which is the one framework finding
with a before and an after:

```sh
uv venv --python 3.11 o && uv pip install --python o/bin/python 'open-interpreter==0.4.3'
o/bin/python -c "import interpreter"      # ModuleNotFoundError: No module named 'pkg_resources'
uv pip install --python o/bin/python 'setuptools<81'
o/bin/python -c "from interpreter import interpreter; print(interpreter.auto_run)"   # False
```

**Check the goose supply-chain finding for yourself.** Do not install it:

```sh
curl -s https://pypi.org/pypi/goose-ai/json \
  | python3 -c "import sys,json;i=json.load(sys.stdin)['info'];print(i['version'],repr(i['summary']),i.get('home_page'))"
```

Compare that to `https://github.com/aaif-goose/goose`, which is Apache-2.0,
written in Rust, releases `v1.57.0`, and publishes no PyPI package at all.

## 5. The environment constraints that blocked execution

These are host facts, not opinions. On the container that produced this
package:

```sh
curl -s "$HTTPS_PROXY/__agentproxy/status" | python3 -m json.tool | grep -A3 recentRelayFailures
#   -> connect_rejected for huggingface.co:443 and registry.ollama.ai:443
cat /proc/self/cgroup | head -3        # cgroup v1, not v2
cat /sys/fs/cgroup/cgroup.controllers  # hugetlb only — no cpu, memory or pids
timedatectl show --property=NTPSynchronized --value   # fails: no systemd as PID 1
```

And the kernel-capability correction, which matters to the forensic record:

```sh
grep -E 'CONFIG_(BPF_LSM|SECURITY_LANDLOCK|KPROBES|TCG_TPM)' /boot/config-$(uname -r)
mount -t securityfs nodev /sys/kernel/security 2>/dev/null; cat /sys/kernel/security/lsm
```

On 6.18.44-fc-v185 this reports `CONFIG_BPF_LSM=y`,
`CONFIG_SECURITY_LANDLOCK=y`, and `lsm=lockdown,capability,landlock,selinux,bpf`
— unlike 6.18.44-fc-v24, the kernel of record in the maturity addendum, where
both were unset.

**Do not read that as a capability.** ADR-008 already records the trap: a
`CONFIG_LSM` string and an LSM list are not evidence that BPF-LSM attach
works. No runtime attach test was performed, so the correct status is
CONFIG-OBSERVED, and `CONFIG_KPROBES`, `CONFIG_TCG_TPM` and `CONFIG_IMA`
remain absent.

## 6. What would make the five framework gates executable

In order, cheapest first:

1. Allow `registry.ollama.ai` through the environment's network policy, or
   provide a model API key as an environment secret. The repository already
   pins `llama3.2:1b` by reviewed manifest digest and provisions it with
   `validation/enterprise/prepare_local_model.py`; CI run 40825279520 step 12
   proves that path works on a GitHub-hosted runner.
2. Run on cgroup v2 with `cpu`, `memory` and `pids` delegated, and with a
   synchronised clock. The existing workflow already installs chrony and
   waits on it.
3. Either provision the `[self-hosted, linux, snifferdog-disposable]` runner
   that `real-agent-live.yml` requires, or add a GitHub-hosted workflow for
   the five frameworks.

Until (1) holds, any framework result would be a smoke test, and the
assignment is explicit that a framework import or smoke test is not a pass.
