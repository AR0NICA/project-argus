"""Closed-world stdlib validation for one completed D0A S02 -> S03 -> S04 run."""
import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 32768
RUN_RE = re.compile(r"^ARGUS-[0-9]{8}-LOCAL-R[0-9]{2}$")
SHA_RE = re.compile(r"^[a-f0-9]{64}$")
UUID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")
COMMON = {"schema_version", "evidence_id", "event_time_utc", "run_id", "stage_id", "event_type", "request_id", "result", "source_ref", "target_ref", "action", "fixture_or_resource_id", "content_sha256", "collector", "reviewer", "redaction_status", "secret_material_present", "fixture_id", "correlation"}


def fail(message):
    raise ValueError(message)


def sha_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_value(value, label):
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(label + " must be a UTC Z timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(label + " is not parseable UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        fail(label + " is not UTC")
    return parsed


def read_json(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(label + " is not valid JSON") from exc


def require_string(item, key):
    if not isinstance(item.get(key), str) or not item[key]:
        fail("event field is not a non-empty string: " + key)


def validate_common(event, run_id, expected_id):
    if not COMMON <= set(event) or event.get("schema_version") != "argus.event/v1":
        fail("missing common event contract field")
    if event.get("evidence_id") != expected_id or event.get("run_id") != run_id:
        fail("unexpected event identity")
    for key in ("stage_id", "event_type", "request_id", "result", "source_ref", "target_ref", "action", "fixture_or_resource_id", "fixture_id", "collector", "redaction_status"):
        require_string(event, key)
    if event.get("reviewer") is not None or event.get("secret_material_present") is not False:
        fail("reviewer/secret material contract violated")
    if not isinstance(event.get("correlation"), dict) or not SHA_RE.fullmatch(event.get("content_sha256", "")):
        fail("event correlation/content hash contract violated")
    return utc_value(event["event_time_utc"], "event_time_utc")


def validate_envelope(envelope, run_id, request_id):
    exact = {"schema_version", "request_id", "run_id", "source", "method", "path", "body_sha256", "evaluation_status"}
    if not isinstance(envelope, dict) or set(envelope) != exact:
        fail("S02 envelope is not the frozen interface")
    if envelope.get("schema_version") != "argus.hybridnb-envelope/v1" or envelope.get("request_id") != request_id or envelope.get("run_id") != run_id:
        fail("S02 envelope identity mismatch")
    if envelope.get("source") != "original_request" or envelope.get("method") != "POST" or envelope.get("path") != "/auth" or envelope.get("evaluation_status") != "disabled_not_evaluated":
        fail("S02 envelope boundary mismatch")
    if not SHA_RE.fullmatch(envelope.get("body_sha256", "")):
        fail("S02 envelope body hash invalid")


def validate_provenance(directory, checkout, run_id):
    provenance = read_json(directory / "provenance.json", "provenance")
    expected = {
        "run_id": run_id,
        "fixture_sha256": sha_file(checkout / "fixtures/d0a-local-fixtures.json"),
        "seed_sha256": sha_file(checkout / "mysql/init.sql"),
        "event_schema_sha256": sha_file(checkout / "schemas/event-v1.json"),
        "hybridnb_schema_sha256": sha_file(checkout / "schemas/hybridnb-request-envelope-v1.json"),
    }
    for key, value in expected.items():
        if provenance.get(key) != value:
            fail("provenance mismatch: " + key)
    if not isinstance(provenance.get("compose_images"), str) or not provenance["compose_images"].strip():
        fail("provenance missing resolved image inventory")


def validate_waf(evidence_root, run_id, auth_request_id, marker_request_id):
    path = evidence_root / "waf-request-tap.jsonl"
    try:
        raw_lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise ValueError("missing WAF request tap") from exc
    records = []
    for raw in raw_lines:
        if len(raw) > MAX_BYTES:
            fail("WAF tap line exceeds 32 KiB")
        try:
            record = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("WAF tap contains invalid JSON") from exc
        if record.get("run_id") == run_id:
            records.append(record)
    def exact(uri, request_id):
        matched = [x for x in records if x.get("schema_version") == "argus.waf-tap/v1" and x.get("uri") == uri and x.get("request_id") == request_id and x.get("method") == "POST" and x.get("status") == 200 and x.get("crs_engine") == "detection_only"]
        if len(matched) != 1:
            fail("missing or duplicate detection-only WAF tap for " + uri)
    exact("/auth", auth_request_id)
    exact("/admin/marker", marker_request_id)


def validate(evidence_root, run_id, checkout):
    if not RUN_RE.fullmatch(run_id):
        fail("invalid frozen run_id")
    directory = evidence_root / run_id
    manifest = read_json(directory / "run-manifest.json", "run manifest")
    expected_manifest = {"manifest_version":"argus.d0a-local-run/v1", "run_id":run_id, "scenario":"D0A-LOCAL", "approval_state":"approved", "concurrency":1, "minimum_interval_seconds":1}
    if manifest != expected_manifest:
        fail("run manifest is not the exact approved contract")
    validate_provenance(directory, checkout, run_id)
    events_path = directory / "events.jsonl"
    try:
        raw_lines = events_path.read_bytes().splitlines()
    except OSError as exc:
        raise ValueError("missing events evidence") from exc
    if len(raw_lines) != 4:
        fail("expected exactly four chain event lines")
    events = []
    for raw in raw_lines:
        if not raw or len(raw) > MAX_BYTES:
            fail("event line is empty or exceeds 32 KiB")
        try:
            events.append(json.loads(raw))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("event line is not valid JSON") from exc
    auth_request_id, marker_request_id = run_id + "-AUTH", run_id + "-MARK"
    expected = [
        ("S02", "E01", "fixed_sqli_auth_fixture", "accepted", "ATK-S02-SYNTH-AUTH-01", auth_request_id, "was", "synthetic_mysql_auth"),
        ("S02", "E02", "hybridnb_adapter", "not_evaluated", "ATK-S02-SYNTH-AUTH-01", auth_request_id, "was", "synthetic_mysql_auth"),
        ("S03", "E03", "administrator_session_issued", "authorized", "ATK-S02-SYNTH-AUTH-01", auth_request_id, "web", "was_fixed_actions"),
        ("S04", "E04", "fixed_marker_written", "written", "ATK-S04-MARKER-01", marker_request_id, "was", "task_local_evidence_volume"),
    ]
    timestamps = []
    for event, (stage, sequence, event_type, result, fixture, request_id, source, target) in zip(events, expected):
        timestamps.append(validate_common(event, run_id, f"{run_id}-{stage}-{sequence}"))
        if (event["stage_id"], event["event_type"], event["result"], event["fixture_id"], event["fixture_or_resource_id"], event["request_id"], event["source_ref"], event["target_ref"], event["action"]) != (stage, event_type, result, fixture, fixture, request_id, source, target, event_type):
            fail("event stage/type/result/fixture/request binding mismatch")
    if timestamps != sorted(timestamps):
        fail("event timestamps are not ordered")
    s02, adapter, issued, s04 = events
    env_a, env_b = s02.get("original_request_envelope"), adapter.get("original_request_envelope")
    validate_envelope(env_a, run_id, auth_request_id)
    validate_envelope(env_b, run_id, auth_request_id)
    if env_a != env_b or env_a["body_sha256"] != s02["content_sha256"] or adapter["content_sha256"] != s02["content_sha256"]:
        fail("S02 original request envelopes/content hashes differ")
    decision = s02["correlation"].get("auth_decision_hash")
    if not SHA_RE.fullmatch(decision or "") or s02["correlation"] != {"principal":"synthetic_admin", "auth_decision_hash":decision} or adapter["correlation"] != {"adapter":"disabled_not_evaluated", "crs_fields_consumed":False}:
        fail("S02 decision or disabled HybridNB adapter mismatch")
    session_hash, ticket_id = issued["correlation"].get("admin_session_hash"), issued["correlation"].get("upload_ticket_id")
    if not SHA_RE.fullmatch(session_hash or "") or not UUID_RE.fullmatch(ticket_id or "") or issued["correlation"] != {"auth_decision_hash":decision, "admin_session_hash":session_hash, "upload_ticket_id":ticket_id, "ttl_seconds":120, "one_time":True} or issued["content_sha256"] != session_hash:
        fail("S03 session/ticket correlation mismatch")
    marker_path = directory / "marker.json"
    try:
        marker_raw = marker_path.read_bytes()
    except OSError as exc:
        raise ValueError("missing marker evidence") from exc
    if len(marker_raw) > MAX_BYTES:
        fail("marker exceeds 32 KiB")
    try:
        marker = json.loads(marker_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("marker is not valid JSON") from exc
    marker_sha = hashlib.sha256(marker_raw).hexdigest()
    marker_required = {"marker_schema_version","run_id","request_id","fixture_id","operation","timestamp_utc","non_destructive","auth_decision_hash","admin_session_hash","upload_ticket_id","web_action_context_id"}
    if set(marker) != marker_required or marker.get("marker_schema_version") != "argus.fixed-marker/v1" or marker.get("run_id") != run_id or marker.get("request_id") != marker_request_id or marker.get("fixture_id") != "ATK-S04-MARKER-01" or marker.get("operation") != "write_fixed_marker" or marker.get("non_destructive") is not True:
        fail("marker contract mismatch")
    utc_value(marker["timestamp_utc"], "marker timestamp")
    if marker.get("auth_decision_hash") != decision or marker.get("admin_session_hash") != issued["correlation"]["admin_session_hash"] or marker.get("upload_ticket_id") != issued["correlation"]["upload_ticket_id"] or not UUID_RE.fullmatch(marker.get("web_action_context_id", "")):
        fail("S03/S04 marker correlation mismatch")
    corr = s04["correlation"]
    expected_s04_correlation = {"web_marker_sha256":marker_sha, "web_action_context_id":marker["web_action_context_id"], "auth_decision_hash":decision, "admin_session_hash":marker["admin_session_hash"], "upload_ticket_id":marker["upload_ticket_id"], "non_destructive":True}
    if corr != expected_s04_correlation:
        fail("S04 marker correlation mismatch")
    if s04.get("content_sha256") != marker_sha or s04.get("response_sha256") != marker_sha:
        fail("S04 content/response hash mismatch")
    validate_waf(evidence_root, run_id, auth_request_id, marker_request_id)
    return "evidence validation passed: exact S02 -> S03 -> S04 chain, WAF tap, provenance, and marker"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", default="evidence")
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        print(validate(Path(args.evidence_root), args.run_id, Path(__file__).resolve().parents[1]))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
