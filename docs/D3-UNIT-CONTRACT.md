# D3-UNIT-STAGES — R0-UNIT local contract

Local, AWS-free implementation of the S01-S10 unit-stage contract, the one-time
handoff chain, the approval harness, and the safety guards. This proves the
contract with synthetic data before any BASE redeploy. The same contract logic is
reused unchanged when R0-UNIT runs against live BASE; only the observed values
differ.

This is a sanitized summary. It contains no account ids, endpoints, CIDRs, ARNs,
credential material, or fixture originals.

## What D3 proves

Each stage is executed independently at least once. The decisive check is not
"the API returned success" but that each stage's **fixed success token** and its
**next-stage handoff** are actually produced and bound to the same `run_id` and
to the predecessor token. Without a valid predecessor token a stage never runs.
The approval harness may inject a missing predecessor for an isolated unit run,
and every injection is recorded — any injection (or an incomplete chain, or
local-synthetic proof) makes the run ineligible as a D4 golden chain.

## Frozen chain

| Stage | fixed success token | handoff to next | action |
|-------|---------------------|-----------------|--------|
| S01 | `endpoint_map_hash` | `endpoint_contract_id` | — |
| S02 | `auth_decision_hash` | `auth_decision_id` | — |
| S03 | `admin_session_hash` | `upload_ticket_id` | — |
| S04 | `web_marker_sha256` | `web_action_context_id` | `MARKER` |
| S05 | `role_identity_hash` | `credential_handoff_id` | `IMDS_IDENTITY` |
| S06 | `external_identity_event_id` | `same_role_session_id` | — |
| S07 | `canary_object_sha256` | `was_bundle_handoff_id` | — |
| S08 | `was_admin_session_hash` | `db_read_ticket_id` | `WAS_AUTH` |
| S09 | `db_result_manifest_id` | `result_handle_id` (row/byte/result hash) | — |
| S10 | `delivery_sha256` | full-run evidence manifest | — |

Handoff tokens are one-time, TTL-bound (120 s), and run-bound. Reuse, forgery,
expiry, cross-run use, wrong-kind, and wrong-consuming-stage are all rejected.

## Safety boundary (unchanged in D3)

- S01 ≤ 12 total requests. **Enforced from evidence**: the S01 primary event
  carries a `request_count` that `guard_s01_requests` rejects above 12 (local
  synthetic uses a fixed count of 3; runtime carries the operator's observed
  count). Only S01 may carry `request_count`.
- S02-S10 one contract request and one control request. **Enforced count**: the
  validator requires the exact per-stage event count — S02 carries two events
  (the contract event plus the frozen HybridNB adapter), every other stage one.
- ≤ 1 rps, concurrency 1, ≥ 1 s between requests.
- Synthetic results only, ≤ 10 rows and ≤ 32 KiB, checked before return in S09/S10.
- Only the `MARKER`, `IMDS_IDENTITY`, `WAS_AUTH` fixed actions; no arbitrary SQL,
  shell, URL, or file path. S07 is exact key+version `GetObject` only — no
  `ListBucket`, write, delete, or policy change.
- No credential material captured; every evidence record is scanned for
  secret-like material and carries `secret_material_present=false`.
- HybridNB stays `disabled_not_evaluated` (D0 freeze). **Enforced for both proof
  kinds**: `assert_hybridnb_frozen` rejects any event carrying a model
  score/label/threshold or an `evaluation_status` other than
  `disabled_not_evaluated`, and S02 must carry exactly one adapter event pinned
  to that status. The runtime collector emits this adapter too, so the freeze is
  checkable on live evidence, not just the local path.

## Two proof kinds

- `local_synthetic` — produced by `run_d3_unit.py` with synthetic data, no AWS.
  Proves the contract, handoff chain, and guards. **Never** counts as D3
  completion and can never be a golden chain.
- `runtime` — produced by `collect_d3_runtime.py` from a live BASE run's observed
  tokens/handoffs plus per-stage **independent** source raw evidence (CloudTrail,
  Flow Logs, RDS audit, S3 data event, ALB access, Nginx/ModSecurity, auditd —
  never the web/was app logs). Required for real D3 close-out.

Both proof kinds are R0-UNIT evidence and therefore always carry
`counts_toward_golden_chain=false`. D4 owns the separate uninjected full-chain
run; a complete S01-S10 D3 runtime export cannot substitute for it.

Runtime raw evidence is validated in its source-native shape (CloudTrail/S3
JSON identity and operation, Flow Log fields/window, ALB/auditd timestamps,
timestamped Nginx/ModSecurity export, and RDS `ARGUS-Q01` row). The validator
also scans raw files and handoff records for secret-like material. Evidence run
IDs are immutable; collectors refuse to overwrite existing derived artifacts.

## Files

- `fixtures/d3-unit-fixtures.json` — frozen contract, mirrored from the core authority.
- `fixtures/d3-runtime-input.example.json` — template for the runtime collector input.
- `schemas/d3-event-v1.json`, `schemas/d3-handoff-token-v1.json`, `schemas/d3-run-manifest-v1.json`.
- `runner/d3_core.py` — handoff/token engine, approval harness, stage contracts, guards.
- `runner/run_d3_unit.py` — R0-UNIT local synthetic runner (writes evidence, self-validates).
- `runner/collect_d3_runtime.py` — assembles `proof_kind=runtime` evidence from operator input.
- `runner/run_d3_gate.py` — gate: `--plan-only` (synthetic) vs `--require-runtime`.
- `scripts/validate_d3_evidence.py` — closed-world post-run validator (both proof kinds).
- `tests/test_d3_contract.py` — engine, evidence, and runtime rejection tests.
- `docs/D3-REDEPLOY-RUNBOOK.md` — BASE rebuild + live R0-UNIT runtime runbook.

## Run and verify (local, no AWS)

```powershell
python scripts/validate_static.py
python -m unittest tests/test_d3_contract.py -v
python runner/run_d3_unit.py --run-id ARGUS-20260824-BASE-R01 --stages all --evidence-root evidence --start-utc 2026-08-24T00:00:00Z
python scripts/validate_d3_evidence.py --evidence-root evidence --run-id ARGUS-20260824-BASE-R01
```

`--stages all` runs S01-S10 in one pass; `--stages S07` runs a single stage with
the harness injecting its predecessor. The local runner only ever emits
`proof_kind=local_synthetic`, which can never be counted as a golden chain.

## Not in scope here (later, gated)

Live-BASE execution of the stage actions, BASE redeploy, and the R0-UNIT
cross-review require a separate redeploy approval and real AWS spend on the
shared account — see `docs/D3-REDEPLOY-RUNBOOK.md`. The runtime collector and
gate are implemented and locally tested here; they only need live-BASE evidence
to run for real.
