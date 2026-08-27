# D4-FULL-CHAIN local contract

D4 proves the **single uninjected S01→S10 causal chain** and binds three of them
into the **R1-BASELINE**. It reuses the frozen S01–S10 unit contract from D3
(`runner/d3_core.py`) unchanged — the stage table, success-token derivation, the
one-time TTL-bound handoff ledger, and the row/byte/action/secret guards. The one
thing D4 owns that D3 never does is the **golden chain**.

Like D3, this contract closes **locally first** (no AWS, no network, no arbitrary
SQL/shell/URL/path input), then the identical checker runs against independently
exported live-BASE evidence. Only the observed values differ.

## What makes a golden chain

`counts_toward_golden_chain=true` is **re-derived from the evidence, never
trusted**, and holds only when **all** of these are true:

1. `proof_kind == "runtime"` — a local synthetic proof can never be golden;
2. every **S01…S10** stage ran and reached its frozen success result, in order;
3. **zero** approval-harness injections — every predecessor handoff was the real
   prior stage's success token;
4. **zero** handoff reuse / expiry / cross-run / wrong-stage errors.

The D4 chain **forbids injection outright**: any harness-injected event or handoff
is rejected, so a valid D4 run always carries an empty injected set. Partial runs,
injected runs, and single-stage proofs belong to **D3-UNIT-STAGES**, not here.

## Two proof kinds

| Proof kind | Producer | Golden? | Meaning |
|---|---|---|---|
| `local_synthetic` | `runner/run_d4_chain.py` | never | the full-chain contract closes end to end, locally |
| `runtime` | `runner/collect_d4_runtime.py` | yes, when eligible | one live-BASE golden chain, corroborated by independent sources |

Independent runtime sources are validated by the **same** machinery as D3
(`scripts/validate_d3_evidence.py`): the vulnerable Web/WAS app logs are excluded,
so the evidence path never depends on the vulnerable app session or EC2 role.

## HybridNB freeze (D0)

S02 carries exactly one HybridNB adapter event pinned to
`disabled_not_evaluated`. No pre-D5 event may carry a model score, label, or
threshold, and HybridNB never changes an allow/block decision. The WAF-vs-HybridNB
four-quadrant evaluation is **D5-DUAL-DETECTION only**.

## R1-BASELINE

Three or more **distinct** run ids, each an independently re-validated runtime
golden chain, establish the baseline (`scripts/validate_d4_baseline.py`,
`runner/run_d4_baseline_gate.py`). The aggregate never re-labels a per-run result:
every member must already stand on its own as a golden chain.

## Commands (local contract, no AWS, no cost)

```powershell
# 1. Close the full-chain contract locally (proof_kind=local_synthetic, never golden)
python runner/run_d4_chain.py --run-id ARGUS-20260827-BASE-R01 --evidence-root evidence --start-utc 2026-08-27T00:00:00Z

# 2. Per-run gate. --plan-only accepts the local proof and is NEVER D4 completion.
python runner/run_d4_gate.py --run-id ARGUS-20260827-BASE-R01 --evidence-root evidence --plan-only

# 3. Assemble a runtime golden chain from independently exported live-BASE evidence
#    (raw files must already sit under evidence/<run_id>/raw/ — see the template below)
python runner/collect_d4_runtime.py --input <runtime-input.json> --evidence-root evidence
python runner/run_d4_gate.py --run-id <run_id> --evidence-root evidence --require-runtime

# 4. Bind three distinct golden chains into R1-BASELINE
python runner/run_d4_baseline_gate.py --evidence-root evidence \
    --run-id ARGUS-20260827-BASE-R01 --run-id ARGUS-20260827-BASE-R02 --run-id ARGUS-20260827-BASE-R03 \
    --write-manifest --baseline-id ARGUS-20260827-BASE-R1BASELINE
```

`fixtures/d4-runtime-input.example.json` is the operator-export **template** — it
shows the shape for all ten stages and will not pass the validator as written.

## Files

- `runner/d4_core.py` — D4 chain engine + golden-chain rule (reuses `d3_core`).
- `runner/run_d4_chain.py` — local synthetic full-chain runner.
- `runner/collect_d4_runtime.py` — runtime golden-chain assembler.
- `runner/run_d4_gate.py` — per-run gate (`--plan-only` / `--require-runtime`).
- `runner/run_d4_baseline_gate.py` — R1-BASELINE aggregate gate.
- `scripts/validate_d4_evidence.py` — closed-world per-run validator.
- `scripts/validate_d4_baseline.py` — R1-BASELINE aggregate validation.
- `schemas/d4-chain-event-v1.json`, `d4-chain-manifest-v1.json`,
  `d4-baseline-manifest-v1.json` (handoff reuses `d3-handoff-token-v1.json`).
- `fixtures/d4-chain-fixtures.json`, `fixtures/d4-runtime-input.example.json`.
- `tests/test_d4_contract.py`.

## What is NOT done here

The local contract and its failure regressions are closed. Actual D4 completion
still needs, in order: a fresh BASE deploy → D1/D2 environment gates → **three**
live-BASE full-chain runs with distinct run ids exported and assembled into
runtime golden chains → cross-review → teardown. No `terraform apply` and no
attack replay belong to this local phase.
