"""ARGUS Web service: D0A fixed actions and the benign-only D1 observation relay."""
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BYTES = 32768
MAX_D1_ROWS = 10
MIN_D1_INTERVAL_SECONDS = 1.0
RUN_RE = re.compile(r"^ARGUS-[0-9]{8}-LOCAL-R[0-9]{2}$")
BASE_RUN_RE = re.compile(r"^ARGUS-[0-9]{8}-BASE-R[0-9]{2}$")
AUTH_FIXTURE, MARKER_FIXTURE = "ATK-S02-SYNTH-AUTH-01", "ATK-S04-MARKER-01"
D1_FIXTURE = "BEN-D1-OBS-001"
PROBE_TOKEN, TTL_SECONDS = "fixture-token-v1", 120
WAS_URL = __import__("os").environ.get("WAS_URL", "http://was:8081")
EVIDENCE_ROOT = __import__("pathlib").Path(os.environ.get("EVIDENCE_ROOT", "/evidence"))
D1_LOG_ROOT = __import__("pathlib").Path(os.environ.get("D1_LOG_ROOT", "/var/log/argus"))
TICKETS, TICKET_LOCK = {}, threading.Lock()
D1_LOCK = threading.BoundedSemaphore(value=1)
D1_RATE_LOCK, D1_LAST_OBSERVE = threading.Lock(), 0.0


def sha(value): return hashlib.sha256(value).hexdigest()
def now(): return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
def valid_run_id(value): return isinstance(value, str) and bool(RUN_RE.fullmatch(value))
def valid_base_run_id(value): return isinstance(value, str) and bool(BASE_RUN_RE.fullmatch(value))
def session_token(run_id): return sha(f"ARGUS-D0A-LOCAL/v1|{run_id}|synthetic_admin|administrator".encode())
def envelope(run_id, request_id, path, raw):
    return {"schema_version": "argus.hybridnb-envelope/v1", "request_id": request_id, "run_id": run_id,
            "source": "original_request", "method": "POST", "path": path, "body_sha256": sha(raw),
            "evaluation_status": "disabled_not_evaluated"}
def append_event(run_id, stage_id, sequence, event_type, request_id, result, **extra):
    event = {"schema_version":"argus.event/v1", "evidence_id":f"{run_id}-{stage_id}-E{sequence:02d}", "event_time_utc":now(),
             "run_id":run_id, "stage_id":stage_id, "event_type":event_type, "request_id":request_id, "result":result,
             "source_ref":"web", "target_ref":"was_fixed_actions", "action":event_type, "fixture_or_resource_id":extra.get("fixture_id", "none"),
             "content_sha256":extra.get("content_sha256", sha(b"")), "collector":"d0a-local-runner", "reviewer":None,
             "redaction_status":"synthetic_no_redaction_required", "secret_material_present":False}
    event.update(extra); wire=(json.dumps(event,separators=(",",":"),sort_keys=True)+"\n").encode()
    if len(wire)>MAX_BYTES: raise ValueError("event exceeds 32 KiB")
    with open(EVIDENCE_ROOT/run_id/"events.jsonl", "ab") as handle: handle.write(wire)
    return event


def was_post(path, body, headers):
    request = urllib.request.Request(WAS_URL + path, data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", **headers}, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read(MAX_BYTES + 1))


def was_get(path, headers):
    request = urllib.request.Request(WAS_URL + path, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=5) as response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("WAS response exceeds 32 KiB")
    return json.loads(raw)


def d1_runtime_config():
    """Read the exact benign AWS targets without accepting request-provided targets."""
    values = {
        "bucket": os.environ.get("D1_S3_BUCKET", ""),
        "key": os.environ.get("D1_S3_KEY", ""),
        "version_id": os.environ.get("D1_S3_OBJECT_VERSION_ID", ""),
        "parameter_name": os.environ.get("D1_SSM_SENTINEL_PARAMETER_NAME", ""),
        "region": os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "")),
    }
    if not all(values.values()) or values["version_id"].lower() == "null":
        raise ValueError("D1 exact AWS runtime configuration is incomplete")
    return values


def d1_aws_observe(config, session_factory=None):
    """Perform only an exact-version GetObject and a sentinel GetParameter.

    boto3 uses the standard AWS credential provider chain, so this is compatible
    with instance roles, container credentials, and local AWS CLI profiles. No
    returned object or parameter value is placed in an application response/log.
    """
    if session_factory is None:
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("AWS SDK is unavailable") from exc
        session_factory = boto3.session.Session
    session = session_factory(region_name=config["region"])
    s3, ssm = session.client("s3"), session.client("ssm")
    response = s3.get_object(Bucket=config["bucket"], Key=config["key"], VersionId=config["version_id"])
    body = response.get("Body")
    if body is None:
        raise ValueError("S3 GetObject response lacks a body")
    try:
        content = body.read(MAX_BYTES + 1)
    finally:
        close = getattr(body, "close", None)
        if close:
            close()
    if not isinstance(content, bytes) or len(content) > MAX_BYTES:
        raise ValueError("S3 object exceeds D1 bound")
    ssm.get_parameter(Name=config["parameter_name"], WithDecryption=False)
    return {
        "s3_version_id": config["version_id"], "s3_content_sha256": sha(content),
        "ssm_parameter_name_sha256": sha(config["parameter_name"].encode()),
    }


def d1_rate_allowed(clock=time.monotonic):
    global D1_LAST_OBSERVE
    with D1_RATE_LOCK:
        current = clock()
        if current - D1_LAST_OBSERVE < MIN_D1_INTERVAL_SECONDS:
            return False
        D1_LAST_OBSERVE = current
        return True


def d1_session_hash(run_id, request_id):
    return sha(f"ARGUS-D1-BASE/v1|{run_id}|{request_id}|{D1_FIXTURE}".encode())


def structured_log(event, **fields):
    print(json.dumps({"service": "web", "event": event, "timestamp": now(), **fields}, separators=(",", ":"), sort_keys=True), flush=True)


def d1_source_log(source, event, **fields):
    """Write one collector-shaped source event without secrets or AWS values."""
    document = {"schema_version":"argus.d1-application-log/v1", "source":source, "service":"web",
        "event":event, "timestamp":now(), **fields}
    wire = (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(wire) > MAX_BYTES:
        raise ValueError("D1 source log exceeds byte bound")
    D1_LOG_ROOT.mkdir(parents=True, exist_ok=True)
    with open(D1_LOG_ROOT / (source + ".jsonl"), "ab") as handle:
        handle.write(wire)
    print(wire.decode("utf-8").rstrip(), flush=True)
    return document
def claim_ticket(run_id, ticket_id, token):
    """Atomically consume a valid one-time ticket before any WAS forward."""
    with TICKET_LOCK:
        ticket = TICKETS.get(ticket_id)
        if not ticket or ticket["run_id"] != run_id or ticket["used"] or ticket["expires"] < time.time() or sha(token.encode()) != ticket["session_hash"]:
            return None
        ticket["used"] = True
        return ticket, str(uuid.uuid4())


class Handler(BaseHTTPRequestHandler):
    server_version = "ARGUS-D0A-Web/1"
    def log_message(self, fmt, *args): print(fmt % args, file=sys.stderr)
    def send_json(self, status, value):
        wire = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        if len(wire) > MAX_BYTES: raise ValueError("response exceeds 32 KiB")
        self.send_response(status); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(wire))); self.end_headers(); self.wfile.write(wire)
    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {"service":"web", "status":"ok"})
        if self.path == "/d1/observe":
            return self.d1_observe()
        self.send_json(404, {"service":"web", "status":"not_found"})
    def do_POST(self):
        try: length = int(self.headers.get("Content-Length", "0"))
        except ValueError: length = 0
        request_id = self.headers.get("X-ARGUS-Request-Id", "")
        if length < 1 or length > MAX_BYTES or not re.fullmatch(r"[A-Za-z0-9._-]{8,128}", request_id):
            return self.send_json(400, {"error":"invalid_bounded_request"})
        try: raw, data = self.rfile.read(length), None; data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError): return self.send_json(400, {"error":"invalid_json"})
        run_id = data.get("run_id")
        if not valid_run_id(run_id) or self.headers.get("X-ARGUS-Run-Id") != run_id:
            return self.send_json(400, {"error":"invalid_run_id"})
        if self.path == "/auth": return self.auth(run_id, request_id, raw, data)
        if self.path == "/admin/marker": return self.marker(run_id, request_id, raw, data)
        self.send_json(404, {"error":"not_found"})
    def auth(self, run_id, request_id, raw, data):
        if data.get("fixture_id") != AUTH_FIXTURE or data.get("probe") != PROBE_TOKEN:
            return self.send_json(403, {"error":"fixture_not_allowed"})
        try:
            decision = was_post("/fixed-auth", {"run_id":run_id,"request_id":request_id,"fixture_id":AUTH_FIXTURE,
                "probe":PROBE_TOKEN,"original_request_sha256":sha(raw)}, {"X-ARGUS-Internal-Caller":"web-d0a"})
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError): return self.send_json(503, {"error":"synthetic_auth_unavailable"})
        token, ticket = session_token(run_id), str(uuid.uuid4())
        session_hash = sha(token.encode()); expires = time.time() + TTL_SECONDS
        with TICKET_LOCK:
            TICKETS[ticket] = {"run_id":run_id,"decision":decision["auth_decision_hash"],"session_hash":session_hash,"expires":expires,"used":False}
        append_event(run_id, "S03", 3, "administrator_session_issued", request_id, "authorized", fixture_id=AUTH_FIXTURE, content_sha256=sha(token.encode()),
            correlation={"auth_decision_hash":decision["auth_decision_hash"], "admin_session_hash":session_hash,
                         "upload_ticket_id":ticket, "ttl_seconds":TTL_SECONDS, "one_time":True})
        return self.send_json(200, {"principal":"synthetic_admin","role":"administrator","session_token":token,
            "auth_decision_hash":decision["auth_decision_hash"],"admin_session_hash":session_hash,"upload_ticket_id":ticket,
            "expires_in_seconds":TTL_SECONDS})
    def marker(self, run_id, request_id, raw, data):
        token, ticket_id = self.headers.get("X-ARGUS-Session", ""), data.get("upload_ticket_id")
        if data.get("fixture_id") != MARKER_FIXTURE or data.get("action") != "write_fixed_marker": return self.send_json(403, {"error":"fixed_action_required"})
        claimed = claim_ticket(run_id, ticket_id, token)
        if not claimed: return self.send_json(401, {"error":"administrator_session_or_one_time_ticket_required"})
        ticket, context = claimed
        try:
            result = was_post("/fixed-marker", {"run_id":run_id,"request_id":request_id,"fixture_id":MARKER_FIXTURE,
                "action":"write_fixed_marker","auth_decision_hash":ticket["decision"],"admin_session_hash":ticket["session_hash"],
                "upload_ticket_id":ticket_id,"web_action_context_id":context,"original_request_sha256":sha(raw)},
                {"X-ARGUS-Internal-Caller":"web-d0a", "X-ARGUS-Session":token})
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError): return self.send_json(503, {"error":"fixed_marker_unavailable"})
        return self.send_json(200, {**result, "web_action_context_id":context})
    def d1_observe(self):
        run_id, request_id = self.headers.get("X-ARGUS-Run-Id", ""), self.headers.get("X-ARGUS-Request-Id", "")
        if not valid_base_run_id(run_id) or not re.fullmatch(r"[A-Za-z0-9._-]{8,128}", request_id):
            return self.send_json(400, {"error": "invalid_d1_run_or_request_id"})
        if self.headers.get("X-ARGUS-Fixture-Id") != D1_FIXTURE:
            return self.send_json(403, {"error": "benign_fixture_required"})
        if not D1_LOCK.acquire(blocking=False):
            return self.send_json(429, {"error": "d1_concurrency_limited"})
        try:
            if not d1_rate_allowed():
                return self.send_json(429, {"error": "d1_rate_limited"})
            try:
                d1_source_log("d0_envelope", "d1_original_request_envelope", run_id=run_id, request_id=request_id,
                    method="GET", path="/d1/observe", body_sha256=sha(b""), fixture_id=D1_FIXTURE,
                    evaluation_status="disabled_not_evaluated", envelope_schema_version="argus.hybridnb-envelope/v1")
                aws_observation = d1_aws_observe(d1_runtime_config())
                was_result = was_get("/d1/observe", {"X-ARGUS-Internal-Caller": "web-d1", "X-ARGUS-Run-Id": run_id,
                    "X-ARGUS-Request-Id": request_id, "X-ARGUS-Fixture-Id": D1_FIXTURE,
                    "X-ARGUS-D1-Aws-Observation": json.dumps(aws_observation, separators=(",", ":"), sort_keys=True)})
            except Exception as exc:
                # SDK/network errors can include AWS identifiers in their message. Keep
                # them out of HTTP responses, application logs, and traceback output.
                structured_log("d1_observe_failed", run_id=run_id, request_id=request_id, fixture_id=D1_FIXTURE, error_class=exc.__class__.__name__)
                return self.send_json(503, {"error": "d1_observation_unavailable"})
            if not isinstance(was_result, dict) or was_result.get("row_count", MAX_D1_ROWS + 1) > MAX_D1_ROWS:
                return self.send_json(502, {"error": "invalid_d1_was_response"})
            d1_source_log("web", "d1_observe_completed", run_id=run_id, request_id=request_id, fixture_id=D1_FIXTURE,
                session_hash=d1_session_hash(run_id, request_id), hybridnb_status="disabled_not_evaluated",
                waf_status="disabled_not_evaluated", row_count=was_result["row_count"])
            self.send_json(200, {"fixture_id": D1_FIXTURE, "run_id": run_id, "request_id": request_id,
                "waf_status": "disabled_not_evaluated", "hybridnb_status": "disabled_not_evaluated", **was_result})
        finally:
            D1_LOCK.release()

if __name__ == "__main__": ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
