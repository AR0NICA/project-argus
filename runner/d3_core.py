"""D3-UNIT-STAGES core: closed-world, stdlib-only stage-contract and handoff engine.

This module performs no AWS calls, no network I/O, and accepts no arbitrary SQL,
shell, URL, or file-path input. It models the S01-S10 unit-stage contracts on
fixed synthetic inputs so the success-token / one-time-handoff chain, the safety
guards (<=10 rows, <=32 KiB, action allow-list, no secret material), and the
approval harness can be built and verified locally before any BASE redeploy.
The same contract logic is reused, unchanged, when R0-UNIT runs against live
BASE; only the observed values differ.
"""
import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

SCHEMA_EVENT = "argus.d3-event/v1"
SCHEMA_HANDOFF = "argus.d3-handoff/v1"
SCHEMA_MANIFEST = "argus.d3-unit-run/v1"
SCHEMA_ENVELOPE = "argus.hybridnb-envelope/v1"

RUN_RE = re.compile(r"^ARGUS-[0-9]{8}-BASE-R[0-9]{2}$")
STAGE_RE = re.compile(r"^S(0[1-9]|10)$")
SHA_RE = re.compile(r"^[a-f0-9]{64}$")
EVENT_ID_RE = re.compile(r"^EVT-[a-f0-9]{32}$")
MANIFEST_ID_RE = re.compile(r"^DBM-[a-f0-9]{32}$")
UUID4_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")

MAX_BYTES = 32768
MAX_ROWS = 10
MIN_INTERVAL_SECONDS = 1
HANDOFF_TTL_SECONDS = 120
S01_MAX_REQUESTS = 12

ALLOWED_ACTIONS = ("MARKER", "IMDS_IDENTITY", "WAS_AUTH")

# Frozen fixed synthetic result for the S09 ARGUS-Q01 query (three benign rows).
ARGUS_Q01_ROWS = [
    {"synthetic_id": 1, "label": "synthetic-alpha", "amount": 10},
    {"synthetic_id": 2, "label": "synthetic-bravo", "amount": 20},
    {"synthetic_id": 3, "label": "synthetic-charlie", "amount": 30},
]

# Single authority for the S01-S10 unit-stage contract. The fixtures file mirrors
# this table for documentation and provenance hashing; this table is the checker.
STAGES = [
    {"stage": "S01", "fixture": "ATK-S01-RECON-01", "action": None, "event_type": "bounded_recon", "result": "read", "success_field": "endpoint_map_hash", "success_type": "hash", "handoff_in": None, "handoff_out": "endpoint_contract_id"},
    {"stage": "S02", "fixture": "ATK-S02-SYNTH-AUTH-01", "action": None, "event_type": "fixed_sqli_auth_fixture", "result": "accepted", "success_field": "auth_decision_hash", "success_type": "hash", "handoff_in": "endpoint_contract_id", "handoff_out": "auth_decision_id"},
    {"stage": "S03", "fixture": "ATK-S03-ADMIN-01", "action": None, "event_type": "administrator_session_issued", "result": "authorized", "success_field": "admin_session_hash", "success_type": "hash", "handoff_in": "auth_decision_id", "handoff_out": "upload_ticket_id"},
    {"stage": "S04", "fixture": "ATK-S04-MARKER-01", "action": "MARKER", "event_type": "fixed_marker_written", "result": "written", "success_field": "web_marker_sha256", "success_type": "hash", "handoff_in": "upload_ticket_id", "handoff_out": "web_action_context_id"},
    {"stage": "S05", "fixture": "ATK-S05-IMDS-01", "action": "IMDS_IDENTITY", "event_type": "imds_role_identity_read", "result": "read", "success_field": "role_identity_hash", "success_type": "hash", "handoff_in": "web_action_context_id", "handoff_out": "credential_handoff_id"},
    {"stage": "S06", "fixture": "ATK-S06-STS-01", "action": None, "event_type": "get_caller_identity", "result": "read", "success_field": "external_identity_event_id", "success_type": "event_id", "handoff_in": "credential_handoff_id", "handoff_out": "same_role_session_id"},
    {"stage": "S07", "fixture": "ATK-S07-CANARY-01", "action": None, "event_type": "exact_version_canary_get", "result": "read", "success_field": "canary_object_sha256", "success_type": "hash", "handoff_in": "same_role_session_id", "handoff_out": "was_bundle_handoff_id"},
    {"stage": "S08", "fixture": "ATK-S08-WASAUTH-01", "action": "WAS_AUTH", "event_type": "was_admin_authenticated", "result": "authorized", "success_field": "was_admin_session_hash", "success_type": "hash", "handoff_in": "was_bundle_handoff_id", "handoff_out": "db_read_ticket_id"},
    {"stage": "S09", "fixture": "ATK-S09-ARGUS-Q01", "action": None, "event_type": "fixed_synthetic_select", "result": "read", "success_field": "db_result_manifest_id", "success_type": "manifest_id", "handoff_in": "db_read_ticket_id", "handoff_out": "result_handle_id"},
    {"stage": "S10", "fixture": "BEN-S10-DELIVERY-01", "action": None, "event_type": "bounded_synthetic_delivery", "result": "delivered", "success_field": "delivery_sha256", "success_type": "hash", "handoff_in": "result_handle_id", "handoff_out": None},
]
SPEC = {item["stage"]: item for item in STAGES}
STAGE_ORDER = [item["stage"] for item in STAGES]
HANDOFF_KINDS = tuple(item["handoff_out"] for item in STAGES if item["handoff_out"])
# For any handoff kind: which stage issues it and what success token kind backs it.
HANDOFF_ISSUER = {
    item["handoff_out"]: {"stage": item["stage"], "field": item["success_field"], "fixture": item["fixture"], "success_type": item["success_type"]}
    for item in STAGES if item["handoff_out"]
}
# For any handoff kind: which stage consumes it (the frozen next stage).
HANDOFF_CONSUMER = {item["handoff_in"]: item["stage"] for item in STAGES if item["handoff_in"]}

FORBIDDEN_PATTERNS = [
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"aws_secret_access_key", re.IGNORECASE),
    re.compile(r"aws_session_token", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bpassword\b", re.IGNORECASE),
]


class D3Error(ValueError):
    """Base class for every D3 contract or safety rejection."""


class HandoffError(D3Error):
    """A handoff token was forged, reused, expired, cross-run, or wrong kind."""


class GuardError(D3Error):
    """A result exceeded the row/byte guard or an action was not allow-listed."""


class SecretLeakError(D3Error):
    """An evidence record contained forbidden secret-like material."""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def utc_text(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_utc(text):
    if not isinstance(text, str) or not text.endswith("Z"):
        raise D3Error("timestamp is not a UTC Z value")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise D3Error("timestamp is not parseable UTC") from exc
    return parsed


def assert_action_allowed(action):
    if action is not None and action not in ALLOWED_ACTIONS:
        raise GuardError("action not on the allow-list: " + str(action))


def guard_result(rows, payload_bytes):
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise GuardError("result exceeds the 10-row guard")
    if not isinstance(payload_bytes, (bytes, bytearray)) or len(payload_bytes) > MAX_BYTES:
        raise GuardError("result exceeds the 32 KiB guard")


def guard_counts(row_count, byte_count):
    if not isinstance(row_count, int) or row_count < 0 or row_count > MAX_ROWS:
        raise GuardError("result row count exceeds the 10-row guard")
    if not isinstance(byte_count, int) or byte_count < 0 or byte_count > MAX_BYTES:
        raise GuardError("result byte count exceeds the 32 KiB guard")


def assert_no_secret(record):
    blob = json.dumps(record, separators=(",", ":"), sort_keys=True)
    for pattern in FORBIDDEN_PATTERNS:
        if pattern.search(blob):
            raise SecretLeakError("evidence record contains forbidden secret-like material")


def success_token(run_id, stage, field, fixture, predecessor_token, success_type):
    base = "|".join(["argus.d3", run_id, stage, field, fixture, predecessor_token or ""])
    digest = sha(base.encode("utf-8"))
    if success_type == "hash":
        return digest
    if success_type == "event_id":
        return "EVT-" + digest[:32]
    if success_type == "manifest_id":
        return "DBM-" + digest[:32]
    raise D3Error("unknown success token type: " + str(success_type))


class HandoffLedger:
    """Issues and consumes one-time, TTL-bound, run-bound handoff tokens."""

    def __init__(self):
        self.records = {}

    def issue(self, kind, run_id, issued_by_stage, predecessor_token, predecessor_kind, now, harness_injected=False, result_handle=None):
        if kind not in HANDOFF_KINDS:
            raise HandoffError("unknown handoff kind: " + str(kind))
        handoff_id = str(uuid.uuid4())
        record = {
            "handoff_schema_version": SCHEMA_HANDOFF,
            "handoff_id": handoff_id,
            "handoff_kind": kind,
            "run_id": run_id,
            "issued_by_stage": issued_by_stage,
            "consumed_by_stage": None,
            "predecessor_success_token": predecessor_token,
            "predecessor_success_kind": predecessor_kind,
            "issued_at_utc": utc_text(now),
            "ttl_seconds": HANDOFF_TTL_SECONDS,
            "not_after_utc": utc_text(now + timedelta(seconds=HANDOFF_TTL_SECONDS)),
            "one_time": True,
            "consumed": False,
            "consumed_at_utc": None,
            "harness_injected": bool(harness_injected),
        }
        if result_handle is not None:
            record["result_handle"] = result_handle
        self.records[handoff_id] = record
        return handoff_id

    def consume(self, handoff_id, run_id, expected_kind, consuming_stage, now):
        record = self.records.get(handoff_id)
        if record is None:
            raise HandoffError("forged or unknown handoff id")
        if record["run_id"] != run_id:
            raise HandoffError("handoff is bound to a different run_id")
        if record["handoff_kind"] != expected_kind:
            raise HandoffError("handoff kind mismatch for " + consuming_stage)
        if HANDOFF_CONSUMER.get(expected_kind) != consuming_stage:
            raise HandoffError("handoff consumed by the wrong stage")
        if record["consumed"]:
            raise HandoffError("handoff already consumed (one-time violation)")
        if now > parse_utc(record["not_after_utc"]):
            raise HandoffError("handoff expired past its TTL")
        record["consumed"] = True
        record["consumed_at_utc"] = utc_text(now)
        record["consumed_by_stage"] = consuming_stage
        return record


class ApprovalHarness:
    """Injects a stage's missing predecessor handoff for an independent unit run.

    Every injection is recorded so the run can never be counted as a golden chain.
    The harness can only issue the frozen handoff kinds; it cannot fabricate a
    success token for a stage that was not run, only a synthetic predecessor.
    """

    def __init__(self, ledger, enabled):
        self.ledger = ledger
        self.enabled = enabled
        self.injected = []

    def inject(self, kind, run_id, now):
        if not self.enabled:
            raise HandoffError("missing predecessor handoff and harness injection is disabled")
        issuer = HANDOFF_ISSUER[kind]
        predecessor_token = success_token(run_id, issuer["stage"], issuer["field"], issuer["fixture"], "", issuer["success_type"])
        result_handle = None
        if kind == "result_handle_id":
            payload = canonical_bytes(ARGUS_Q01_ROWS)
            result_handle = {"row_count": len(ARGUS_Q01_ROWS), "byte_count": len(payload), "result_sha256": sha(payload), "db_query_id": "ARGUS-Q01"}
        handoff_id = self.ledger.issue(kind, run_id, "harness", predecessor_token, issuer["success_type"], now, harness_injected=True, result_handle=result_handle)
        self.injected.append(kind)
        return handoff_id


def validate_run_id(run_id):
    if not isinstance(run_id, str) or not RUN_RE.fullmatch(run_id):
        raise D3Error("invalid frozen BASE run_id")
    return run_id


def _build_event(run_id, stage, seq, event_type, result, request_id, fixture, source, target, action, content_sha, success_kind, success_value, handoff_in_id, handoff_out_id, harness_injected, now, extra=None):
    event = {
        "schema_version": SCHEMA_EVENT,
        "evidence_id": "%s-%s-E%02d" % (run_id, stage, seq),
        "event_time_utc": utc_text(now),
        "run_id": run_id,
        "stage_id": stage,
        "event_type": event_type,
        "request_id": request_id,
        "result": result,
        "source_ref": source,
        "target_ref": target,
        "action": action,
        "fixture_or_resource_id": fixture,
        "content_sha256": content_sha,
        "collector": "d3-unit-runner",
        "reviewer": None,
        "redaction_status": "synthetic_no_redaction_required",
        "secret_material_present": False,
        "success_token_kind": success_kind,
        "success_token_value": success_value,
        "handoff_in_id": handoff_in_id,
        "handoff_out_id": handoff_out_id,
        "handoff_injected": bool(harness_injected),
        "harness_injected": bool(harness_injected),
        "counts_toward_golden_chain": False,
    }
    if extra:
        event.update(extra)
    assert_no_secret(event)
    return event


def run_unit(run_id, stages, harness_allowed, start_utc):
    """Execute the requested unit stages in order and return the evidence bundle.

    A stage never proceeds without a validated one-time predecessor handoff. Any
    handoff the approval harness injects is recorded. This is the LOCAL SYNTHETIC
    runner: it always emits proof_kind=local_synthetic and can never produce a
    golden chain. R0-UNIT evidence is never a D4 golden-chain execution.
    """
    proof_kind = "local_synthetic"
    validate_run_id(run_id)
    if not stages:
        raise D3Error("no stages requested")
    for stage in stages:
        if stage not in SPEC:
            raise D3Error("unknown stage: " + str(stage))
    if stages != sorted(stages, key=STAGE_ORDER.index):
        raise D3Error("stages must be requested in S01..S10 order")
    if start_utc.tzinfo is None:
        start_utc = start_utc.replace(tzinfo=timezone.utc)

    ledger = HandoffLedger()
    harness = ApprovalHarness(ledger, enabled=harness_allowed)
    prior = {}
    events = []
    now = start_utc
    first = True

    for stage in stages:
        spec = SPEC[stage]
        if not first:
            now = now + timedelta(seconds=MIN_INTERVAL_SECONDS)
        first = False
        request_id = "%s-%s-REQ" % (run_id, stage)
        assert_action_allowed(spec["action"])

        handoff_in_id = None
        predecessor_token = ""
        harness_injected = False
        if spec["handoff_in"]:
            kind = spec["handoff_in"]
            if kind in prior:
                handoff_in_id = prior.pop(kind)
            else:
                handoff_in_id = harness.inject(kind, run_id, now)
                harness_injected = True
            record = ledger.consume(handoff_in_id, run_id, kind, stage, now)
            predecessor_token = record["predecessor_success_token"]

        if stage == "S01" and S01_MAX_REQUESTS > 12:  # frozen recon budget guard
            raise GuardError("S01 recon budget exceeds 12 requests")

        content_sha = sha(canonical_bytes({"run_id": run_id, "stage": stage, "fixture": spec["fixture"], "predecessor": predecessor_token}))
        success_value = success_token(run_id, stage, spec["success_field"], spec["fixture"], predecessor_token, spec["success_type"])

        result_handle = None
        extra = {"correlation": {"success_field": spec["success_field"]}}
        if stage == "S09":
            payload = canonical_bytes(ARGUS_Q01_ROWS)
            guard_result(ARGUS_Q01_ROWS, payload)
            result_handle = {"row_count": len(ARGUS_Q01_ROWS), "byte_count": len(payload), "result_sha256": sha(payload), "db_query_id": "ARGUS-Q01"}
            extra["result_guard"] = result_handle
            extra["correlation"]["db_query_id"] = "ARGUS-Q01"
        if stage == "S10":
            handle = record.get("result_handle") if spec["handoff_in"] else None
            if not isinstance(handle, dict):
                raise D3Error("S10 requires a result handle from S09")
            guard_counts(handle.get("row_count"), handle.get("byte_count"))
            extra["result_guard"] = {"row_count": handle["row_count"], "byte_count": handle["byte_count"], "result_sha256": handle["result_sha256"]}

        handoff_out_id = None
        if spec["handoff_out"]:
            handoff_out_id = ledger.issue(spec["handoff_out"], run_id, stage, success_value, spec["success_type"], now, result_handle=result_handle)
            prior[spec["handoff_out"]] = handoff_out_id

        events.append(_build_event(run_id, stage, 1, spec["event_type"], spec["result"], request_id, spec["fixture"], "test_terminal" if stage == "S01" else "argus_web", spec.get("target", "argus_was"), spec["action"] or "none", content_sha, spec["success_type"], success_value, handoff_in_id, handoff_out_id, harness_injected, now, extra))

        if stage == "S02":
            adapter = {"correlation": {"adapter": "disabled_not_evaluated", "crs_fields_consumed": False, "evaluation_status": "disabled_not_evaluated"}}
            events.append(_build_event(run_id, stage, 2, "hybridnb_adapter", "not_evaluated", request_id, spec["fixture"], "argus_web", "hybridnb_interface", "none", content_sha, spec["success_type"], success_value, handoff_in_id, None, harness_injected, now, adapter))

    # R0-UNIT proves unit-stage contracts only. It never counts toward the D4
    # uninjected golden-chain execution, regardless of proof kind or coverage.
    counts_golden = False
    for event in events:
        event["counts_toward_golden_chain"] = counts_golden

    handoffs = list(ledger.records.values())
    manifest = {
        "manifest_version": SCHEMA_MANIFEST,
        "run_id": run_id,
        "scenario": "D3-UNIT-STAGES",
        "experiment_group": "R0-UNIT",
        "approval_state": "approved",
        "proof_kind": proof_kind,
        "concurrency": 1,
        "minimum_interval_seconds": 1,
        "max_result_rows": MAX_ROWS,
        "max_result_bytes": MAX_BYTES,
        "stages_executed": list(stages),
        "harness_injected_handoffs": list(harness.injected),
        "counts_toward_golden_chain": counts_golden,
    }
    return {"manifest": manifest, "events": events, "handoffs": handoffs}
