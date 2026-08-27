"""Closed-world stdlib validation for one completed D4-FULL-CHAIN run.

It re-derives the S01-S10 contract from the frozen authority in runner/d3_core.py
and the D4 golden-chain rule from runner/d4_core.py, then rejects: a run that is
not the complete uninjected chain; forged / reused / expired / cross-run /
wrong-stage handoffs; any approval-harness injection (forbidden in D4); results
over the 10-row / 32 KiB guard; disallowed actions; any pre-D5 model
score/label/threshold; and any secret-like material. It performs no AWS calls and
replays nothing. The independent runtime-source machinery is reused unchanged from
validate_d3_evidence so "independent evidence" means exactly one thing project-wide.
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "scripts"))
import d3_core as core  # noqa: E402
import d4_core as d4  # noqa: E402
import validate_d3_evidence as d3v  # noqa: E402

read_json = d3v.read_json
read_jsonl = d3v.read_jsonl
sha_file = d3v.sha_file
parse_window = d3v.parse_window
validate_runtime_source = d3v.validate_runtime_source

EVENT_REQUIRED = {"schema_version", "evidence_id", "event_time_utc", "run_id", "stage_id", "event_type", "request_id", "result", "source_ref", "target_ref", "action", "fixture_or_resource_id", "content_sha256", "collector", "reviewer", "redaction_status", "secret_material_present", "success_token_kind", "success_token_value", "handoff_in_id", "handoff_out_id", "harness_injected", "counts_toward_golden_chain"}
HANDOFF_KEYS = {"handoff_schema_version", "handoff_id", "handoff_kind", "run_id", "issued_by_stage", "consumed_by_stage", "predecessor_success_token", "predecessor_success_kind", "issued_at_utc", "ttl_seconds", "not_after_utc", "one_time", "consumed", "consumed_at_utc", "harness_injected"}


def fail(message):
    raise core.D3Error(message)


def expected_provenance(checkout, run_id):
    return {
        "run_id": run_id,
        "chain_fixture_sha256": sha_file(checkout / "fixtures/d4-chain-fixtures.json"),
        "event_schema_sha256": sha_file(checkout / "schemas/d4-chain-event-v1.json"),
        "handoff_schema_sha256": sha_file(checkout / "schemas/d3-handoff-token-v1.json"),
        "manifest_schema_sha256": sha_file(checkout / "schemas/d4-chain-manifest-v1.json"),
        "d3_core_sha256": sha_file(checkout / "runner/d3_core.py"),
        "d4_core_sha256": sha_file(checkout / "runner/d4_core.py"),
        "d3_validator_sha256": sha_file(checkout / "scripts/validate_d3_evidence.py"),
        "d4_validator_sha256": sha_file(checkout / "scripts/validate_d4_evidence.py"),
        "runtime_collector_sha256": sha_file(checkout / "runner/collect_d4_runtime.py"),
    }


def validate_provenance(directory, checkout, run_id):
    provenance = read_json(directory / "provenance.json", "provenance")
    if provenance != expected_provenance(checkout, run_id):
        fail("provenance does not match the current checkout")


def validate_manifest(directory, run_id):
    manifest = read_json(directory / "run-manifest.json", "run manifest")
    required = {"manifest_version", "run_id", "scenario", "experiment_group", "approval_state", "proof_kind", "concurrency", "minimum_interval_seconds", "max_result_rows", "max_result_bytes", "stages_executed", "harness_injected_handoffs", "counts_toward_golden_chain"}
    keys = set(manifest)
    if not required <= keys or keys - required - {"run_window"}:
        fail("run manifest is not the exact D4 contract shape")
    if manifest["manifest_version"] != d4.SCHEMA_MANIFEST or manifest["run_id"] != run_id or manifest["scenario"] != d4.SCENARIO or manifest["experiment_group"] != d4.EXPERIMENT_GROUP or manifest["approval_state"] != "approved":
        fail("run manifest identity mismatch")
    if manifest["proof_kind"] not in ("local_synthetic", "runtime") or manifest["concurrency"] != 1 or manifest["minimum_interval_seconds"] != 1 or manifest["max_result_rows"] != core.MAX_ROWS or manifest["max_result_bytes"] != core.MAX_BYTES:
        fail("run manifest safety constants mismatch")
    if manifest.get("proof_kind") == "runtime" and "run_window" not in keys:
        fail("runtime proof requires a run_window")
    if manifest.get("proof_kind") == "local_synthetic" and "run_window" in keys:
        fail("local synthetic proof must not carry a run_window")
    stages = manifest["stages_executed"]
    if list(stages) != list(d4.FULL_CHAIN):
        fail("D4 requires the complete S01..S10 chain in order")
    if manifest["harness_injected_handoffs"] != []:
        fail("the D4 chain forbids approval-harness injection")
    return manifest


def validate_event_common(event, run_id):
    if not EVENT_REQUIRED <= set(event) or event.get("schema_version") != d4.SCHEMA_EVENT:
        fail("event is missing a required D4 field")
    if event["run_id"] != run_id or event["stage_id"] not in core.SPEC:
        fail("event run/stage identity mismatch")
    for key in ("event_type", "request_id", "source_ref", "target_ref", "action", "fixture_or_resource_id", "redaction_status", "success_token_value"):
        if not isinstance(event.get(key), str) or not event[key]:
            fail("event field is not a non-empty string: " + key)
    if event.get("reviewer") is not None or event.get("secret_material_present") is not False:
        fail("event reviewer/secret material contract violated")
    if event.get("harness_injected") is not False or event.get("handoff_injected", False) is not False:
        fail("D4 events must not be harness/handoff injected")
    if not core.SHA_RE.fullmatch(event.get("content_sha256", "")):
        fail("event content hash is not a sha256")
    if event["stage_id"] != "S01" and "request_count" in event:
        fail("only S01 may carry a request_count")
    core.assert_no_secret(event)
    core.assert_hybridnb_frozen(event)
    core.assert_action_allowed(event["action"] if event["action"] != "none" else None)


def validate_success_token(event):
    kind, value = event["success_token_kind"], event["success_token_value"]
    spec = core.SPEC[event["stage_id"]]
    if kind != spec["success_type"]:
        fail("success token kind mismatch for " + event["stage_id"])
    if kind == "hash" and not core.SHA_RE.fullmatch(value):
        fail("hash success token is not a sha256")
    if kind == "event_id" and not core.EVENT_ID_RE.fullmatch(value):
        fail("event_id success token is malformed")
    if kind == "manifest_id" and not core.MANIFEST_ID_RE.fullmatch(value):
        fail("manifest_id success token is malformed")


def validate_result_guard(event):
    stage = event["stage_id"]
    if stage not in ("S09", "S10"):
        return
    guard = event.get("result_guard")
    expected_keys = {"row_count", "byte_count", "result_sha256", "db_query_id"} if stage == "S09" else {"row_count", "byte_count", "result_sha256"}
    if not isinstance(guard, dict) or set(guard) != expected_keys or not core.SHA_RE.fullmatch(guard.get("result_sha256", "")):
        fail(stage + " is missing a result guard")
    if stage == "S09" and guard["db_query_id"] != "ARGUS-Q01":
        fail("S09 result guard is not bound to ARGUS-Q01")
    core.guard_counts(guard["row_count"], guard["byte_count"])


def validate_primary_contract(event):
    """Pin every primary event to its stage authority, not merely to globally
    allowed values. This prevents a valid action, fixture, or event type from a
    different stage being substituted into an otherwise well-shaped chain."""
    stage = event["stage_id"]
    spec = core.SPEC[stage]
    expected = {
        "event_type": spec["event_type"],
        "result": spec["result"],
        "action": spec["action"] or "none",
        "fixture_or_resource_id": spec["fixture"],
    }
    for key, value in expected.items():
        if event.get(key) != value:
            fail(stage + " " + key + " does not match the frozen stage contract")
    correlation = {"success_field": spec["success_field"]}
    if stage == "S09":
        correlation["db_query_id"] = "ARGUS-Q01"
    if event.get("correlation") != correlation:
        fail(stage + " correlation does not match the frozen stage contract")


def validate_adapter_contract(adapter, primary_s02):
    if adapter.get("event_type") != "hybridnb_adapter" or adapter.get("result") != "not_evaluated" or adapter.get("action") != "none":
        fail("S02 HybridNB adapter identity mismatch")
    if adapter.get("fixture_or_resource_id") != core.SPEC["S02"]["fixture"] or adapter.get("source_ref") != "argus_web" or adapter.get("target_ref") != "hybridnb_interface":
        fail("S02 HybridNB adapter source/target/fixture mismatch")
    if adapter.get("correlation") != core.HYBRIDNB_ADAPTER:
        fail("S02 HybridNB adapter is not the exact disabled_not_evaluated freeze")
    for key in ("event_time_utc", "request_id", "content_sha256", "collector", "redaction_status", "success_token_kind", "success_token_value", "handoff_in_id", "counts_toward_golden_chain"):
        if adapter.get(key) != primary_s02.get(key):
            fail("S02 HybridNB adapter is detached from its primary event: " + key)
    if adapter.get("handoff_out_id") is not None:
        fail("S02 HybridNB adapter must not issue a handoff")


def validate_handoff_record(record, run_id):
    if set(record) - {"result_handle"} != HANDOFF_KEYS or record.get("handoff_schema_version") != core.SCHEMA_HANDOFF:
        fail("handoff record is not the exact contract shape")
    if record["run_id"] != run_id:
        fail("handoff is bound to a different run_id")
    if not core.UUID4_RE.fullmatch(record.get("handoff_id", "")):
        fail("handoff id is not a uuid4")
    if record["handoff_kind"] not in core.HANDOFF_KINDS:
        fail("handoff kind is unknown")
    if record["ttl_seconds"] != core.HANDOFF_TTL_SECONDS or record["one_time"] is not True:
        fail("handoff TTL/one-time contract violated")
    if record["harness_injected"] is not False or record["issued_by_stage"] == "harness":
        fail("the D4 chain forbids harness-injected handoffs")
    if record["issued_by_stage"] not in core.SPEC:
        fail("handoff must be issued by a real stage")
    issuer = core.HANDOFF_ISSUER.get(record["handoff_kind"])
    if issuer is None or record["issued_by_stage"] != issuer["stage"] or record["predecessor_success_kind"] != issuer["success_type"]:
        fail("handoff issuer or predecessor success kind mismatch")
    issued, not_after = core.parse_utc(record["issued_at_utc"]), core.parse_utc(record["not_after_utc"])
    if (not_after - issued).total_seconds() != core.HANDOFF_TTL_SECONDS:
        fail("handoff not_after does not equal issued + TTL")
    expected_consumer = core.HANDOFF_CONSUMER.get(record["handoff_kind"])
    if record["consumed"]:
        if record["consumed_by_stage"] != expected_consumer:
            fail("handoff consumed by the wrong stage")
        consumed = core.parse_utc(record["consumed_at_utc"])
        if consumed < issued or consumed > not_after:
            fail("handoff consumed outside its validity window")
    elif record["consumed_by_stage"] is not None or record["consumed_at_utc"] is not None:
        fail("unconsumed handoff carries consumption fields")
    if record["issued_by_stage"] == "S09":
        if not isinstance(record.get("result_handle"), dict):
            fail("S09 handoff must carry a result handle")
    elif "result_handle" in record:
        fail("only the S09 handoff may carry a result handle")
    core.assert_no_secret(record)


def validate(evidence_root, run_id, checkout):
    core.validate_run_id(run_id)
    directory = Path(evidence_root) / run_id
    validate_provenance(directory, checkout, run_id)
    manifest = validate_manifest(directory, run_id)
    stages = manifest["stages_executed"]

    events = read_jsonl(directory / "events.jsonl", "events evidence")
    handoffs = read_jsonl(directory / "handoffs.jsonl", "handoffs evidence")
    if not events:
        fail("no events recorded")

    seen_seq = {}
    primary = {}
    last_time = None
    ordered_stages = []
    for event in events:
        validate_event_common(event, run_id)
        validate_success_token(event)
        validate_result_guard(event)
        stage = event["stage_id"]
        seen_seq.setdefault(stage, 0)
        seen_seq[stage] += 1
        expected_id = "%s-%s-E%02d" % (run_id, stage, seen_seq[stage])
        if event["evidence_id"] != expected_id:
            fail("evidence id is not sequential per stage: " + event["evidence_id"])
        moment = core.parse_utc(event["event_time_utc"])
        if seen_seq[stage] == 1:
            ordered_stages.append(stage)
            if last_time is not None and (moment - last_time).total_seconds() < core.MIN_INTERVAL_SECONDS:
                fail("requests are spaced under the 1 rps minimum interval")
            last_time = moment
            primary[stage] = event

    # The complete chain, in order: exactly S01..S10, each with a primary event
    # whose result is the frozen success result for that stage.
    if ordered_stages != list(d4.FULL_CHAIN):
        fail("event stage order is not the complete S01..S10 chain")
    for stage in d4.FULL_CHAIN:
        if stage not in primary:
            fail("chain is incomplete: missing stage " + stage)
        if primary[stage]["result"] != core.SPEC[stage]["result"]:
            fail("stage " + stage + " did not reach its frozen success result")
        validate_primary_contract(primary[stage])
        expected = 2 if stage == "S02" else 1
        if seen_seq.get(stage, 0) != expected:
            fail("stage " + stage + " does not carry the exact contract event count")

    # S01 recon budget (<=12 requests), enforced from evidence.
    core.guard_s01_requests(primary["S01"].get("request_count"))

    # D0 freeze: S02 carries exactly one HybridNB adapter pinned disabled_not_evaluated.
    adapters = [event for event in events if event["stage_id"] == "S02" and event.get("event_type") == "hybridnb_adapter"]
    if len(adapters) != 1:
        fail("S02 must carry exactly one HybridNB adapter event")
    validate_adapter_contract(adapters[0], primary["S02"])

    index = {}
    for record in handoffs:
        validate_handoff_record(record, run_id)
        if record["handoff_id"] in index:
            fail("duplicate handoff id")
        index[record["handoff_id"]] = record

    expected_handoff_ids = {primary[stage]["handoff_out_id"] for stage in d4.FULL_CHAIN if core.SPEC[stage]["handoff_out"]}
    consumed_handoff_ids = {primary[stage]["handoff_in_id"] for stage in d4.FULL_CHAIN if core.SPEC[stage]["handoff_in"]}
    if len(handoffs) != len(d4.FULL_CHAIN) - 1 or set(index) != expected_handoff_ids or consumed_handoff_ids != expected_handoff_ids:
        fail("handoff ledger is not the exact closed S01..S10 chain")

    for stage in d4.FULL_CHAIN:
        spec = core.SPEC[stage]
        event = primary[stage]
        predecessor_token = ""
        if spec["handoff_in"]:
            record = index.get(event["handoff_in_id"])
            if record is None or record["handoff_kind"] != spec["handoff_in"] or not record["consumed"] or record["consumed_by_stage"] != stage:
                fail("stage " + stage + " has no valid consumed predecessor handoff")
            issuer_stage = core.HANDOFF_ISSUER[record["handoff_kind"]]["stage"]
            if record["issued_by_stage"] != issuer_stage:
                fail("stage " + stage + " predecessor was not issued by the real prior stage")
            if issuer_stage not in primary or primary[issuer_stage]["success_token_value"] != record["predecessor_success_token"]:
                fail("stage " + stage + " predecessor token is not the real prior stage success token")
            if record["issued_at_utc"] != primary[issuer_stage]["event_time_utc"] or record["consumed_at_utc"] != event["event_time_utc"]:
                fail("stage " + stage + " handoff timestamps are detached from issuer/consumer events")
            predecessor_token = record["predecessor_success_token"]
        elif event["handoff_in_id"] is not None:
            fail("stage " + stage + " must not consume a handoff")

        expected_success = core.success_token(run_id, stage, spec["success_field"], spec["fixture"], predecessor_token, spec["success_type"])
        if event["success_token_value"] != expected_success:
            fail("stage " + stage + " success token does not re-derive from the frozen causal contract")

        if spec["handoff_out"]:
            record = index.get(event["handoff_out_id"])
            if record is None or record["handoff_kind"] != spec["handoff_out"] or record["issued_by_stage"] != stage:
                fail("stage " + stage + " did not issue its handoff")
            if record["predecessor_success_token"] != event["success_token_value"]:
                fail("issued handoff is not bound to this stage success token")
            if record["issued_at_utc"] != event["event_time_utc"]:
                fail("stage " + stage + " handoff issue time is detached from the issuer event")
            if stage == "S09":
                if record["result_handle"] != event.get("result_guard"):
                    fail("S09 result handle is detached from the S09 result guard")
                delivered = primary["S10"].get("result_guard")
                expected_delivered = {key: record["result_handle"][key] for key in ("row_count", "byte_count", "result_sha256")}
                if delivered != expected_delivered:
                    fail("S10 result guard is detached from the S09 result handle")
        elif event["handoff_out_id"] is not None:
            fail("stage " + stage + " must not issue a handoff")

    # Golden-chain accounting is D4's alone and is re-derived, never trusted.
    eligibility = d4.golden_eligibility(manifest["proof_kind"], stages, manifest["harness_injected_handoffs"])
    expected_golden = eligibility["counts_toward_golden_chain"]
    if manifest["counts_toward_golden_chain"] != expected_golden:
        fail("counts_toward_golden_chain does not match the re-derived eligibility")
    for event in events:
        if event["counts_toward_golden_chain"] != expected_golden:
            fail("event golden-chain flag disagrees with the run")

    if manifest["proof_kind"] == "runtime":
        window_start, window_end = parse_window(manifest["run_window"])
        for stage in d4.FULL_CHAIN:
            event = primary[stage]
            event_time = core.parse_utc(event["event_time_utc"])
            if not window_start <= event_time <= window_end:
                fail("runtime stage " + stage + " event time is outside the run window")
            sources = event.get("runtime_sources")
            if not isinstance(sources, list) or not sources:
                fail("runtime stage " + stage + " has no independent source corroboration")
            for record in sources:
                validate_runtime_source(directory, stage, record, window_start, window_end)
    else:
        for event in events:
            if "runtime_sources" in event:
                fail("local synthetic evidence must not carry runtime_sources")

    return "d4 evidence validation passed: %d stage(s), %d handoff(s), proof=%s, golden_chain=%s" % (len(stages), len(handoffs), manifest["proof_kind"], expected_golden)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", default="evidence")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        print(validate(Path(args.evidence_root), args.run_id, ROOT))
    except core.D3Error as exc:
        raise SystemExit(str(exc)) from exc
