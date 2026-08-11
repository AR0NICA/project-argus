"""D0A Web: proxy a fixed WAS auth decision, issue a TTL one-time session ticket."""
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
RUN_RE = re.compile(r"^ARGUS-[0-9]{8}-LOCAL-R[0-9]{2}$")
AUTH_FIXTURE, MARKER_FIXTURE = "ATK-S02-SYNTH-AUTH-01", "ATK-S04-MARKER-01"
PROBE_TOKEN, TTL_SECONDS = "fixture-token-v1", 120
WAS_URL = __import__("os").environ.get("WAS_URL", "http://was:8081")
EVIDENCE_ROOT = __import__("pathlib").Path(os.environ.get("EVIDENCE_ROOT", "/evidence"))
TICKETS, TICKET_LOCK = {}, threading.Lock()


def sha(value): return hashlib.sha256(value).hexdigest()
def now(): return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
def valid_run_id(value): return isinstance(value, str) and bool(RUN_RE.fullmatch(value))
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
    def do_GET(self): self.send_json(200 if self.path == "/health" else 404, {"service":"web", "status":"ok" if self.path == "/health" else "not_found"})
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

if __name__ == "__main__": ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
