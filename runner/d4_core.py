"""D4-FULL-CHAIN core: the single uninjected S01->S10 causal chain and the
R1-BASELINE golden-chain accounting.

D4 reuses the frozen S01-S10 unit contract in runner/d3_core.py unchanged (the
STAGES table, success-token derivation, one-time TTL-bound handoff ledger, and
the row/byte/action/secret guards). It performs no AWS calls, no network I/O, and
accepts no arbitrary SQL, shell, URL, or file-path input.

The one thing D4 owns that D3 never does is the golden chain. A run
`counts_toward_golden_chain=true` only when ALL of the following hold, checked
from the evidence and never trusted:

  * proof_kind == "runtime"                (never a local synthetic proof),
  * every S01..S10 stage ran and succeeded (the complete chain, in order),
  * zero approval-harness injections       (every predecessor handoff was the
                                            real prior stage's success token),
  * zero handoff reuse / expiry / cross-run / wrong-stage errors.

Because the D4 chain forbids injection outright, a valid D4 run always carries an
empty harness-injected set; the local synthetic runner still proves the contract
end to end but can never be golden (its proof_kind is local_synthetic). R1-BASELINE
binds three golden chains under three distinct run ids.
"""
from datetime import timedelta, timezone

import d3_core as core

SCHEMA_EVENT = "argus.d4-chain-event/v1"
SCHEMA_MANIFEST = "argus.d4-full-chain-run/v1"
SCHEMA_BASELINE = "argus.d4-r1-baseline/v1"

SCENARIO = "D4-FULL-CHAIN"
EXPERIMENT_GROUP = "R1-BASELINE"

# The D4 chain is the whole attack chain, S01..S10 in order. Nothing less is a
# golden chain; a partial run is a D3-UNIT-STAGES concern.
FULL_CHAIN = tuple(core.STAGE_ORDER)
# Three independent golden chains (distinct run ids) establish the R1 baseline.
MIN_GOLDEN_RUNS = 3

# Re-export the shared contract authority so callers depend on one source.
D4Error = core.D3Error
HandoffError = core.HandoffError
GuardError = core.GuardError
SecretLeakError = core.SecretLeakError


def golden_eligibility(proof_kind, stages_executed, harness_injected_handoffs):
    """Derive golden-chain eligibility from the three positive conditions.

    Handoff integrity (no reuse / expiry / cross-run / wrong-stage) is a
    precondition, not a field here: any such violation makes the run or its
    validation fail before this is reached. `counts_toward_golden_chain` is the
    conjunction of the conditions below.
    """
    full_chain = list(stages_executed) == list(FULL_CHAIN)
    zero_injection = len(list(harness_injected_handoffs)) == 0
    proof_is_runtime = proof_kind == "runtime"
    return {
        "full_chain": full_chain,
        "zero_injection": zero_injection,
        "proof_is_runtime": proof_is_runtime,
        "counts_toward_golden_chain": bool(full_chain and zero_injection and proof_is_runtime),
    }


def build_chain_event(run_id, stage, seq, collector, content_sha, success_value, handoff_in_id, handoff_out_id, now, counts_golden, extra=None):
    """Shape one D4 chain evidence event. Every field mirrors the D3 event so the
    shared runtime-source and handoff machinery applies, but the schema version
    and collector are D4's and no event is ever harness-injected."""
    spec = core.SPEC[stage]
    event = {
        "schema_version": SCHEMA_EVENT,
        "evidence_id": "%s-%s-E%02d" % (run_id, stage, seq),
        "event_time_utc": core.utc_text(now),
        "run_id": run_id,
        "stage_id": stage,
        "event_type": spec["event_type"],
        "request_id": "%s-%s-REQ" % (run_id, stage),
        "result": spec["result"],
        "source_ref": "test_terminal" if stage == "S01" else "argus_web",
        "target_ref": spec.get("target", "argus_was"),
        "action": spec["action"] or "none",
        "fixture_or_resource_id": spec["fixture"],
        "content_sha256": content_sha,
        "collector": collector,
        "reviewer": None,
        "redaction_status": "synthetic_no_redaction_required",
        "secret_material_present": False,
        "success_token_kind": spec["success_type"],
        "success_token_value": success_value,
        "handoff_in_id": handoff_in_id,
        "handoff_out_id": handoff_out_id,
        "handoff_injected": False,
        "harness_injected": False,
        "counts_toward_golden_chain": bool(counts_golden),
    }
    if extra:
        event.update(extra)
    core.assert_no_secret(event)
    core.assert_hybridnb_frozen(event)
    return event


def build_adapter_event(run_id, seq, collector, content_sha, success_value, handoff_in_id, now, counts_golden):
    """The D0-frozen HybridNB adapter event for S02: pinned to
    disabled_not_evaluated, carrying no model score/label and driving no
    allow/block decision. WAF-vs-HybridNB evaluation is D5 only."""
    spec = core.SPEC["S02"]
    event = {
        "schema_version": SCHEMA_EVENT,
        "evidence_id": "%s-S02-E%02d" % (run_id, seq),
        "event_time_utc": core.utc_text(now),
        "run_id": run_id,
        "stage_id": "S02",
        "event_type": "hybridnb_adapter",
        "request_id": "%s-S02-REQ" % run_id,
        "result": "not_evaluated",
        "source_ref": "argus_web",
        "target_ref": "hybridnb_interface",
        "action": "none",
        "fixture_or_resource_id": spec["fixture"],
        "content_sha256": content_sha,
        "collector": collector,
        "reviewer": None,
        "redaction_status": "synthetic_no_redaction_required",
        "secret_material_present": False,
        "success_token_kind": spec["success_type"],
        "success_token_value": success_value,
        "handoff_in_id": handoff_in_id,
        "handoff_out_id": None,
        "handoff_injected": False,
        "harness_injected": False,
        "counts_toward_golden_chain": bool(counts_golden),
        "correlation": dict(core.HYBRIDNB_ADAPTER),
    }
    core.assert_no_secret(event)
    core.assert_hybridnb_frozen(event)
    return event


def run_chain(run_id, start_utc, collector="d4-chain-runner"):
    """Execute the whole S01->S10 chain with NO approval-harness injection and
    return the local synthetic evidence bundle.

    Every stage consumes the real one-time handoff its predecessor issued; a
    missing predecessor is a hard chain break, never a synthetic injection. This
    is the LOCAL SYNTHETIC driver: proof_kind=local_synthetic, so the run proves
    the full-chain contract but can never count as a golden chain. Runtime golden
    chains are assembled by collect_d4_runtime from independently exported
    live-BASE evidence.
    """
    core.validate_run_id(run_id)
    if start_utc.tzinfo is None:
        start_utc = start_utc.replace(tzinfo=timezone.utc)

    ledger = core.HandoffLedger()
    prior = {}
    events = []
    now = start_utc
    first = True

    for stage in FULL_CHAIN:
        spec = core.SPEC[stage]
        if not first:
            now = now + timedelta(seconds=core.MIN_INTERVAL_SECONDS)
        first = False
        core.assert_action_allowed(spec["action"])

        handoff_in_id = None
        predecessor_token = ""
        record = None
        if spec["handoff_in"]:
            kind = spec["handoff_in"]
            if kind not in prior:
                # D4 forbids injection: a missing predecessor is a real chain break.
                raise HandoffError("D4 chain break: no real predecessor handoff for " + stage)
            handoff_in_id = prior.pop(kind)
            record = ledger.consume(handoff_in_id, run_id, kind, stage, now)
            predecessor_token = record["predecessor_success_token"]

        content_sha = core.sha(core.canonical_bytes({"run_id": run_id, "stage": stage, "fixture": spec["fixture"], "predecessor": predecessor_token}))
        success_value = core.success_token(run_id, stage, spec["success_field"], spec["fixture"], predecessor_token, spec["success_type"])

        result_handle = None
        extra = {"correlation": {"success_field": spec["success_field"]}}
        if stage == "S01":
            core.guard_s01_requests(core.S01_SYNTHETIC_REQUESTS)
            extra["request_count"] = core.S01_SYNTHETIC_REQUESTS
        if stage == "S09":
            payload = core.canonical_bytes(core.ARGUS_Q01_ROWS)
            core.guard_result(core.ARGUS_Q01_ROWS, payload)
            result_handle = {"row_count": len(core.ARGUS_Q01_ROWS), "byte_count": len(payload), "result_sha256": core.sha(payload), "db_query_id": "ARGUS-Q01"}
            extra["result_guard"] = result_handle
            extra["correlation"]["db_query_id"] = "ARGUS-Q01"
        if stage == "S10":
            handle = record.get("result_handle") if record else None
            if not isinstance(handle, dict):
                raise D4Error("S10 requires a result handle from S09")
            core.guard_counts(handle.get("row_count"), handle.get("byte_count"))
            extra["result_guard"] = {"row_count": handle["row_count"], "byte_count": handle["byte_count"], "result_sha256": handle["result_sha256"]}

        handoff_out_id = None
        if spec["handoff_out"]:
            handoff_out_id = ledger.issue(spec["handoff_out"], run_id, stage, success_value, spec["success_type"], now, result_handle=result_handle)
            prior[spec["handoff_out"]] = handoff_out_id

        events.append(build_chain_event(run_id, stage, 1, collector, content_sha, success_value, handoff_in_id, handoff_out_id, now, counts_golden=False, extra=extra))
        if stage == "S02":
            events.append(build_adapter_event(run_id, 2, collector, content_sha, success_value, handoff_in_id, now, counts_golden=False))

    eligibility = golden_eligibility("local_synthetic", FULL_CHAIN, [])
    counts_golden = eligibility["counts_toward_golden_chain"]  # False: local synthetic
    for event in events:
        event["counts_toward_golden_chain"] = counts_golden

    manifest = build_manifest(run_id, "local_synthetic", list(FULL_CHAIN), [], counts_golden, run_window=None)
    handoffs = list(ledger.records.values())
    return {"manifest": manifest, "events": events, "handoffs": handoffs}


def build_manifest(run_id, proof_kind, stages_executed, harness_injected_handoffs, counts_golden, run_window=None):
    manifest = {
        "manifest_version": SCHEMA_MANIFEST,
        "run_id": run_id,
        "scenario": SCENARIO,
        "experiment_group": EXPERIMENT_GROUP,
        "approval_state": "approved",
        "proof_kind": proof_kind,
        "concurrency": 1,
        "minimum_interval_seconds": 1,
        "max_result_rows": core.MAX_ROWS,
        "max_result_bytes": core.MAX_BYTES,
        "stages_executed": list(stages_executed),
        "harness_injected_handoffs": list(harness_injected_handoffs),
        "counts_toward_golden_chain": bool(counts_golden),
    }
    if run_window is not None:
        manifest["run_window"] = run_window
    return manifest
