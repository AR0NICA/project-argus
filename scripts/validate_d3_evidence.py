"""Closed-world stdlib validation for one completed D3 R0-UNIT stage run.

It re-derives the S01-S10 contract from the frozen authority in runner/d3_core.py
and rejects forged, reused, expired, cross-run, or wrong-stage handoffs; results
over the 10-row / 32 KiB guard; disallowed actions; and any secret-like material.
It performs no AWS calls and replays nothing.
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runner"))
import d3_core as core  # noqa: E402

MAX_BYTES = core.MAX_BYTES
MAX_EXPORTED_RAW_BYTES = 1048576
# Independent detection sources allowed to corroborate each stage. The vulnerable
# application logs (web/was) are deliberately excluded: the D2/D3 invariant is
# that the evidence path never depends on the vulnerable app session or EC2 role.
RUNTIME_SOURCES = {
    "S01": {"alb_access", "nginx_modsecurity", "flow_logs"},
    "S02": {"nginx_modsecurity", "rds_audit"},
    "S03": {"nginx_modsecurity", "alb_access"},
    "S04": {"auditd", "nginx_modsecurity", "alb_access"},
    "S05": {"auditd"},
    "S06": {"cloudtrail"},
    "S07": {"cloudtrail", "s3_data_event"},
    "S08": {"flow_logs"},
    "S09": {"flow_logs", "rds_audit"},
    "S10": {"alb_access"},
}
SOURCE_MARKERS = {
    "alb_access": ("Root=1-",),
    "nginx_modsecurity": ("nginx",),
    "auditd": ("audit(",),
    "flow_logs": ("eni-",),
    "cloudtrail": ("eventID",),
    "s3_data_event": ("GetObject",),
    "rds_audit": ("ARGUS-Q01",),
}
SOURCE_RECORD_KEYS = {"source", "event_time_utc", "evidence_path", "content_sha256", "collector", "redaction_status", "native_record_id", "anchors"}
HANDOFF_KEYS = {"handoff_schema_version", "handoff_id", "handoff_kind", "run_id", "issued_by_stage", "consumed_by_stage", "predecessor_success_token", "predecessor_success_kind", "issued_at_utc", "ttl_seconds", "not_after_utc", "one_time", "consumed", "consumed_at_utc", "harness_injected"}
EVENT_REQUIRED = {"schema_version", "evidence_id", "event_time_utc", "run_id", "stage_id", "event_type", "request_id", "result", "source_ref", "target_ref", "action", "fixture_or_resource_id", "content_sha256", "collector", "reviewer", "redaction_status", "secret_material_present", "success_token_kind", "success_token_value", "handoff_in_id", "handoff_out_id", "harness_injected", "counts_toward_golden_chain"}


def fail(message):
    raise core.D3Error(message)


def sha_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise core.D3Error(label + " is not valid JSON") from exc


def read_jsonl(path, label):
    try:
        raw_lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise core.D3Error("missing " + label) from exc
    rows = []
    for raw in raw_lines:
        if not raw:
            continue
        if len(raw) > MAX_BYTES:
            fail(label + " line exceeds 32 KiB")
        try:
            rows.append(json.loads(raw))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise core.D3Error(label + " has an invalid JSON line") from exc
    return rows


def validate_provenance(directory, checkout, run_id):
    provenance = read_json(directory / "provenance.json", "provenance")
    expected = {
        "run_id": run_id,
        "fixture_sha256": sha_file(checkout / "fixtures/d3-unit-fixtures.json"),
        "event_schema_sha256": sha_file(checkout / "schemas/d3-event-v1.json"),
        "handoff_schema_sha256": sha_file(checkout / "schemas/d3-handoff-token-v1.json"),
        "manifest_schema_sha256": sha_file(checkout / "schemas/d3-run-manifest-v1.json"),
        "core_sha256": sha_file(checkout / "runner/d3_core.py"),
    }
    if provenance != expected:
        fail("provenance does not match the current checkout")


def validate_manifest(directory, run_id):
    manifest = read_json(directory / "run-manifest.json", "run manifest")
    required = {"manifest_version", "run_id", "scenario", "experiment_group", "approval_state", "proof_kind", "concurrency", "minimum_interval_seconds", "max_result_rows", "max_result_bytes", "stages_executed", "harness_injected_handoffs", "counts_toward_golden_chain"}
    keys = set(manifest)
    if not required <= keys or keys - required - {"run_window"}:
        fail("run manifest is not the exact D3 contract shape")
    if manifest.get("proof_kind") == "runtime" and "run_window" not in keys:
        fail("runtime proof requires a run_window")
    if manifest.get("proof_kind") == "local_synthetic" and "run_window" in keys:
        fail("local synthetic proof must not carry a run_window")
    if manifest["manifest_version"] != core.SCHEMA_MANIFEST or manifest["run_id"] != run_id or manifest["scenario"] != "D3-UNIT-STAGES" or manifest["experiment_group"] != "R0-UNIT" or manifest["approval_state"] != "approved":
        fail("run manifest identity mismatch")
    if manifest["proof_kind"] not in ("local_synthetic", "runtime") or manifest["concurrency"] != 1 or manifest["minimum_interval_seconds"] != 1 or manifest["max_result_rows"] != core.MAX_ROWS or manifest["max_result_bytes"] != core.MAX_BYTES:
        fail("run manifest safety constants mismatch")
    stages = manifest["stages_executed"]
    if not stages or any(s not in core.SPEC for s in stages) or stages != sorted(stages, key=core.STAGE_ORDER.index):
        fail("stages_executed is empty, unknown, or out of order")
    if not isinstance(manifest["harness_injected_handoffs"], list) or any(k not in core.HANDOFF_KINDS for k in manifest["harness_injected_handoffs"]):
        fail("harness_injected_handoffs contains an unknown kind")
    return manifest


def validate_event_common(event, run_id):
    if not EVENT_REQUIRED <= set(event) or event.get("schema_version") != core.SCHEMA_EVENT:
        fail("event is missing a required D3 field")
    if event["run_id"] != run_id or event["stage_id"] not in core.SPEC:
        fail("event run/stage identity mismatch")
    for key in ("event_type", "request_id", "source_ref", "target_ref", "action", "fixture_or_resource_id", "redaction_status", "success_token_value"):
        if not isinstance(event.get(key), str) or not event[key]:
            fail("event field is not a non-empty string: " + key)
    if event.get("reviewer") is not None or event.get("secret_material_present") is not False:
        fail("event reviewer/secret material contract violated")
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
    if not isinstance(guard, dict) or "row_count" not in guard or "byte_count" not in guard or not core.SHA_RE.fullmatch(guard.get("result_sha256", "")):
        fail(stage + " is missing a result guard")
    core.guard_counts(guard["row_count"], guard["byte_count"])


def validate_handoff_record(record, run_id):
    if set(record) - {"result_handle"} != HANDOFF_KEYS or record.get("handoff_schema_version") != core.SCHEMA_HANDOFF:
        fail("handoff record is not the exact D3 shape")
    if record["run_id"] != run_id:
        fail("handoff is bound to a different run_id")
    if not core.UUID4_RE.fullmatch(record.get("handoff_id", "")):
        fail("handoff id is not a uuid4")
    if record["handoff_kind"] not in core.HANDOFF_KINDS:
        fail("handoff kind is unknown")
    if record["ttl_seconds"] != core.HANDOFF_TTL_SECONDS or record["one_time"] is not True:
        fail("handoff TTL/one-time contract violated")
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
    if record["harness_injected"] and record["issued_by_stage"] != "harness":
        fail("harness-injected handoff must be issued by the harness")
    if not record["harness_injected"] and record["issued_by_stage"] not in core.SPEC:
        fail("non-injected handoff must be issued by a real stage")
    core.assert_no_secret(record)


def parse_window(window):
    if not isinstance(window, dict) or set(window) != {"start_utc", "end_utc"}:
        fail("run window contract mismatch")
    start, end = core.parse_utc(window["start_utc"]), core.parse_utc(window["end_utc"])
    if (end - start).total_seconds() <= 0:
        fail("run window must be positive")
    return start, end


def exported_raw(directory, relative_path):
    if not isinstance(relative_path, str) or not relative_path or Path(relative_path).is_absolute():
        fail("runtime evidence path must be a non-empty relative path")
    relative = Path(relative_path)
    if not relative.parts or relative.parts[0] != "raw":
        fail("runtime evidence path must be under the run's raw directory")
    root = directory.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise core.D3Error("runtime evidence path escapes the run directory") from exc
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise core.D3Error("runtime exported raw evidence is missing") from exc
    if not raw or len(raw) > MAX_EXPORTED_RAW_BYTES:
        fail("runtime exported raw evidence is empty or exceeds the bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise core.D3Error("runtime exported raw evidence must be UTF-8") from exc
    return raw, text


def matching_line(text, anchors, markers, stage, source):
    matches = [line for line in text.splitlines() if all(value in line for value in anchors + list(markers))]
    if not matches:
        fail(stage + " runtime raw evidence has no single native record containing all anchors for " + source)
    return matches[0]


def validate_native_time(stage, source, descriptor_time, native_time, window_start, window_end):
    if not window_start <= native_time <= window_end:
        fail(stage + " " + source + " native timestamp is outside the run window")
    if abs((native_time - descriptor_time).total_seconds()) > 1:
        fail(stage + " " + source + " descriptor timestamp does not match the native record")


def json_records(text, stage, source):
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise core.D3Error(stage + " " + source + " raw evidence must be native JSON") from exc
    if isinstance(value, dict) and isinstance(value.get("Records"), list):
        return value["Records"]
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    fail(stage + " " + source + " raw JSON has no records")


def validate_cloudtrail(stage, source, text, record, descriptor_time, window_start, window_end):
    matches = [item for item in json_records(text, stage, source) if isinstance(item, dict) and item.get("eventID") == record["native_record_id"]]
    if len(matches) != 1:
        fail(stage + " " + source + " must contain exactly one matching eventID")
    item = matches[0]
    native_text = json.dumps(item, separators=(",", ":"), sort_keys=True)
    if any(anchor not in native_text for anchor in record["anchors"]):
        fail(stage + " " + source + " anchors do not resolve to the matching native event")
    native_time = core.parse_utc(item.get("eventTime", ""))
    validate_native_time(stage, source, descriptor_time, native_time, window_start, window_end)
    if stage == "S06":
        if item.get("eventSource") != "sts.amazonaws.com" or item.get("eventName") != "GetCallerIdentity":
            fail("S06 CloudTrail proof must be sts:GetCallerIdentity")
    elif stage == "S07":
        params = item.get("requestParameters")
        if item.get("eventSource") != "s3.amazonaws.com" or item.get("eventName") != "GetObject" or not isinstance(params, dict) or not params.get("key") or not params.get("versionId"):
            fail("S07 CloudTrail/S3 proof must be exact key+version GetObject")


def validate_line_source(stage, source, text, record, descriptor_time, window_start, window_end):
    anchors = record["anchors"]
    line = matching_line(text, anchors, SOURCE_MARKERS[source], stage, source)
    if source == "alb_access":
        fields = line.split()
        if len(fields) < 3 or fields[0] not in {"http", "https", "h2", "ws", "wss"}:
            fail(stage + " ALB proof is not a native access-log row")
        native_time = core.parse_utc(fields[1])
    elif source == "auditd":
        match = re.search(r"audit\((\d+(?:\.\d+)?):\d+\)", line)
        if not match:
            fail(stage + " auditd proof lacks a native audit(epoch:serial) id")
        native_time = datetime.fromtimestamp(float(match.group(1)), tz=timezone.utc)
    elif source == "flow_logs":
        fields = line.split()
        if len(fields) < 14 or not fields[0].isdigit() or not fields[2].startswith("eni-"):
            fail(stage + " Flow Logs proof is not a native versioned row")
        try:
            start_epoch, end_epoch = int(fields[10]), int(fields[11])
        except ValueError as exc:
            raise core.D3Error(stage + " Flow Logs proof has invalid epoch fields") from exc
        if fields[12] not in {"ACCEPT", "REJECT"} or fields[13] not in {"OK", "NODATA", "SKIPDATA"}:
            fail(stage + " Flow Logs proof has invalid action/log-status")
        flow_start = datetime.fromtimestamp(start_epoch, tz=timezone.utc)
        flow_end = datetime.fromtimestamp(end_epoch, tz=timezone.utc)
        if flow_end < flow_start or not flow_start <= descriptor_time <= flow_end:
            fail(stage + " Flow Logs descriptor time is outside the native row interval")
        if flow_end < window_start or flow_start > window_end:
            fail(stage + " Flow Logs native interval is outside the run window")
        return
    elif source == "nginx_modsecurity":
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise core.D3Error(stage + " Nginx/ModSecurity proof must be a timestamped JSON export") from exc
        if not isinstance(item, dict):
            fail(stage + " Nginx/ModSecurity proof must be a JSON object")
        timestamp = item.get("event_time_utc") or item.get("timestamp") or item.get("time_iso8601")
        native_time = core.parse_utc(timestamp)
    elif source == "rds_audit":
        match = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", line)
        if not match or "ARGUS-Q01" not in line:
            fail(stage + " RDS proof must be a timestamped native ARGUS-Q01 row")
        native_time = core.parse_utc(match.group(0))
    else:
        fail(stage + " has no source-native validator for " + source)
    validate_native_time(stage, source, descriptor_time, native_time, window_start, window_end)


def validate_runtime_source(directory, stage, record, window_start, window_end):
    if not isinstance(record, dict) or set(record) != SOURCE_RECORD_KEYS:
        fail(stage + " runtime source record fields mismatch")
    source = record["source"]
    if source not in RUNTIME_SOURCES[stage]:
        fail(stage + " runtime source is not an allowed independent source: " + str(source))
    if not isinstance(record["collector"], str) or not record["collector"] or not isinstance(record["redaction_status"], str) or not record["redaction_status"]:
        fail(stage + " runtime collector/redaction invalid")
    if not core.SHA_RE.fullmatch(record.get("content_sha256", "")):
        fail(stage + " runtime content hash invalid")
    if not isinstance(record["native_record_id"], str) or not record["native_record_id"]:
        fail(stage + " runtime native record id invalid")
    anchors = record["anchors"]
    if not isinstance(anchors, list) or not anchors or any(not isinstance(a, str) or not a for a in anchors):
        fail(stage + " runtime anchors invalid")
    if record["native_record_id"] not in anchors:
        fail(stage + " runtime native record id must be one of the anchors")
    descriptor_time = core.parse_utc(record["event_time_utc"])
    if not window_start <= descriptor_time <= window_end:
        fail(stage + " runtime source time is outside the run window")
    raw, text = exported_raw(directory, record["evidence_path"])
    if hashlib.sha256(raw).hexdigest() != record["content_sha256"]:
        fail(stage + " runtime exported raw evidence hash mismatch")
    core.assert_no_secret({"runtime_raw": text})
    for marker in SOURCE_MARKERS[source]:
        if marker not in text:
            fail(stage + " runtime raw evidence lacks the native source marker for " + source)
    for anchor in anchors:
        if anchor not in text:
            fail(stage + " runtime raw evidence is missing a declared anchor")
    if source in {"cloudtrail", "s3_data_event"}:
        validate_cloudtrail(stage, source, text, record, descriptor_time, window_start, window_end)
    else:
        validate_line_source(stage, source, text, record, descriptor_time, window_start, window_end)
    return source


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

    # Per-stage sequential evidence ids and ordered, >=1s spaced requests.
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
    if ordered_stages != stages:
        fail("event stage order does not match the manifest")

    # Per-stage event count is fixed by the contract: S02 carries the extra
    # HybridNB adapter event, every other stage exactly one primary event.
    for stage in stages:
        expected = 2 if stage == "S02" else 1
        if seen_seq.get(stage, 0) != expected:
            fail("stage " + stage + " does not carry the exact contract event count")

    # S01 recon request budget (frozen at <=12 requests), enforced from evidence
    # rather than trusted operator discipline.
    if "S01" in primary:
        core.guard_s01_requests(primary["S01"].get("request_count"))

    # D0 freeze: S02 must carry exactly one HybridNB adapter event pinned to
    # disabled_not_evaluated. It never drives an allow/block decision pre-D5.
    if "S02" in stages:
        adapters = [event for event in events if event["stage_id"] == "S02" and event.get("event_type") == "hybridnb_adapter"]
        if len(adapters) != 1:
            fail("S02 must carry exactly one HybridNB adapter event")
        correlation = adapters[0].get("correlation")
        if not isinstance(correlation, dict) or correlation.get("evaluation_status") != "disabled_not_evaluated" or correlation.get("crs_fields_consumed") is not False:
            fail("S02 HybridNB adapter is not pinned to the disabled_not_evaluated freeze")

    index = {}
    for record in handoffs:
        validate_handoff_record(record, run_id)
        if record["handoff_id"] in index:
            fail("duplicate handoff id")
        index[record["handoff_id"]] = record

    injected_kinds = []
    for stage in stages:
        spec = core.SPEC[stage]
        event = primary[stage]
        if spec["handoff_in"]:
            handoff_id = event["handoff_in_id"]
            record = index.get(handoff_id)
            if record is None or record["handoff_kind"] != spec["handoff_in"] or not record["consumed"] or record["consumed_by_stage"] != stage:
                fail("stage " + stage + " has no valid consumed predecessor handoff")
            if record["harness_injected"]:
                injected_kinds.append(record["handoff_kind"])
                issuer = core.HANDOFF_ISSUER[record["handoff_kind"]]
                expected = core.success_token(run_id, issuer["stage"], issuer["field"], issuer["fixture"], "", issuer["success_type"])
                if record["predecessor_success_token"] != expected:
                    fail("injected predecessor token is not the frozen synthetic value")
            else:
                issuer_stage = record["issued_by_stage"]
                if issuer_stage not in primary or primary[issuer_stage]["success_token_value"] != record["predecessor_success_token"]:
                    fail("predecessor token is not bound to the issuing stage success token")
        elif event["handoff_in_id"] is not None:
            fail("stage " + stage + " must not consume a handoff")
        if spec["handoff_out"]:
            handoff_id = event["handoff_out_id"]
            record = index.get(handoff_id)
            if record is None or record["handoff_kind"] != spec["handoff_out"] or record["issued_by_stage"] != stage:
                fail("stage " + stage + " did not issue its handoff")
            if record["predecessor_success_token"] != event["success_token_value"]:
                fail("issued handoff is not bound to this stage success token")
            if stage == "S09" and not isinstance(record.get("result_handle"), dict):
                fail("S09 handoff must carry a result handle")
        elif event["handoff_out_id"] is not None:
            fail("stage " + stage + " must not issue a handoff")

    if sorted(injected_kinds) != sorted(manifest["harness_injected_handoffs"]):
        fail("manifest harness injections do not match the handoff evidence")
    # This validator is scoped to D3-UNIT-STAGES / R0-UNIT. D4 owns the only
    # uninjected end-to-end golden-chain accounting.
    expected_golden = False
    if manifest["counts_toward_golden_chain"] != expected_golden:
        fail("counts_toward_golden_chain does not match the evidence")
    for event in events:
        if event["counts_toward_golden_chain"] != expected_golden:
            fail("event golden-chain flag disagrees with the run")

    if manifest["proof_kind"] == "runtime":
        window_start, window_end = parse_window(manifest["run_window"])
        for stage in stages:
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

    return "d3 evidence validation passed: %d stage(s), %d handoff(s), proof=%s, golden_chain=%s" % (len(stages), len(handoffs), manifest["proof_kind"], expected_golden)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", default="evidence")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        print(validate(Path(args.evidence_root), args.run_id, ROOT))
    except core.D3Error as exc:
        raise SystemExit(str(exc)) from exc
