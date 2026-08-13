"""ARGUS WAS: D0A fixed actions plus bounded benign D1 synthetic observation."""
import hashlib, json, os, re, sys, threading, time, uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import mysql.connector

MAX_BYTES = 32768
MAX_D1_ROWS = 10
MIN_D1_INTERVAL_SECONDS = 1.0
RUN_RE = re.compile(r"^ARGUS-[0-9]{8}-LOCAL-R[0-9]{2}$")
BASE_RUN_RE = re.compile(r"^ARGUS-[0-9]{8}-BASE-R[0-9]{2}$")
AUTH_FIXTURE, MARKER_FIXTURE = "ATK-S02-SYNTH-AUTH-01", "ATK-S04-MARKER-01"
D1_FIXTURE = "BEN-D1-OBS-001"
EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "/evidence"))
D1_LOG_ROOT = Path(os.environ.get("D1_LOG_ROOT", "/var/log/argus"))
D1_AUDIT_MARKER_PATH = Path("/var/lib/argus/d1/audit/argus-d1-observe.marker")
D1_LOCK = threading.BoundedSemaphore(value=1)
D1_RATE_LOCK, D1_LAST_OBSERVE = threading.Lock(), 0.0
def sha(value): return hashlib.sha256(value).hexdigest()
def now(): return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
def valid_run_id(value): return isinstance(value, str) and bool(RUN_RE.fullmatch(value))
def valid_base_run_id(value): return isinstance(value, str) and bool(BASE_RUN_RE.fullmatch(value))
def session_token(run_id): return sha(f"ARGUS-D0A-LOCAL/v1|{run_id}|synthetic_admin|administrator".encode())
def manifest_approved(run_id):
    path = EVIDENCE_ROOT / run_id / "run-manifest.json"
    try: item = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError): return False
    return item == {"manifest_version":"argus.d0a-local-run/v1", "run_id":run_id, "scenario":"D0A-LOCAL", "approval_state":"approved", "concurrency":1, "minimum_interval_seconds":1}
def append_event(run_id, stage, sequence, event_type, request_id, result, **extra):
    event = {"schema_version":"argus.event/v1", "evidence_id":f"{run_id}-{stage}-E{sequence:02d}", "event_time_utc":now(), "run_id":run_id,
             "stage_id":stage,"event_type":event_type,"request_id":request_id,"result":result,"source_ref":"was",
             "target_ref":"synthetic_mysql_auth" if stage=="S02" else "task_local_evidence_volume", "action":event_type,
             "fixture_or_resource_id":extra.get("fixture_id", "none"), "content_sha256":extra.get("content_sha256", sha(b"")),
             "collector":"d0a-local-runner", "reviewer":None, "redaction_status":"synthetic_no_redaction_required", "secret_material_present":False}; event.update(extra)
    wire = (json.dumps(event, separators=(",",":"), sort_keys=True)+"\n").encode()
    if len(wire) > MAX_BYTES: raise ValueError("event exceeds 32 KiB")
    with open(EVIDENCE_ROOT/run_id/"events.jsonl", "ab") as handle: handle.write(wire)
    return event
def synthetic_auth():
    db = mysql.connector.connect(host=os.environ.get("DB_HOST","db"), database=os.environ.get("DB_NAME","argus_synthetic"), user=os.environ.get("DB_USER","argus_local"), password=os.environ.get("DB_PASSWORD","argus_local_only"))
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT username, role FROM users WHERE username = 'not_a_user' OR id = 1 LIMIT 1")
        return cursor.fetchone()
    finally: db.close()


def structured_log(event, **fields):
    """Write source-native JSON to stdout without database values or credentials."""
    print(json.dumps({"service":"was", "event":event, "timestamp":now(), **fields}, separators=(",", ":"), sort_keys=True), flush=True)


def d1_source_log(event, **fields):
    document = {"schema_version":"argus.d1-application-log/v1", "source":"was", "service":"was",
        "event":event, "timestamp":now(), **fields}
    wire = (json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(wire) > MAX_BYTES:
        raise ValueError("D1 source log exceeds byte bound")
    D1_LOG_ROOT.mkdir(parents=True, exist_ok=True)
    with open(D1_LOG_ROOT / "was.jsonl", "ab") as handle:
        handle.write(wire)
    print(wire.decode("utf-8").rstrip(), flush=True)
    return document


def d1_rate_allowed(clock=time.monotonic):
    global D1_LAST_OBSERVE
    with D1_RATE_LOCK:
        current = clock()
        if current - D1_LAST_OBSERVE < MIN_D1_INTERVAL_SECONDS:
            return False
        D1_LAST_OBSERVE = current
        return True


def d1_db_password():
    secret_file = os.environ.get("DB_PASSWORD_FILE", "")
    if secret_file:
        raw = Path(secret_file).read_bytes()
        if not raw or len(raw) > 4096:
            raise ValueError("D1 database secret file is invalid")
        return raw.decode("utf-8").rstrip("\r\n")
    return os.environ.get("DB_PASSWORD", "")


def d1_synthetic_select(request_id, query_id):
    """Query a fixed synthetic relation with an observable, nonsecret query ID."""
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,128}", request_id) or not re.fullmatch(r"[a-f0-9-]{36}", query_id):
        raise ValueError("invalid D1 query ID")
    db = mysql.connector.connect(host=os.environ.get("DB_HOST", "db"), database=os.environ.get("DB_NAME", "argus_synthetic"),
        user=os.environ.get("DB_USER", "argus_d1_reader"), password=d1_db_password())
    try:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT record_id, category, summary FROM d1_synthetic_records WHERE fixture_id = %s ORDER BY record_id LIMIT 10 /* argus_d1_query_id=" + query_id + " argus_request_id=" + request_id + " */", (D1_FIXTURE,))
        rows = cursor.fetchmany(MAX_D1_ROWS + 1)
    finally:
        db.close()
    if len(rows) > MAX_D1_ROWS:
        raise ValueError("D1 result exceeds row bound")
    return rows


def write_d1_audit_marker(run_id, request_id, query_id):
    """Create/update the one fixed auditd-watchable marker; no caller chooses its path."""
    D1_AUDIT_MARKER_PATH.parent.mkdir(parents=True, exist_ok=True)
    marker = {"schema_version":"argus.d1-audit-marker/v1", "run_id":run_id, "request_id":request_id,
        "fixture_id":D1_FIXTURE, "query_id":query_id, "timestamp_utc":now()}
    wire = (json.dumps(marker, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    if len(wire) > MAX_BYTES:
        raise ValueError("D1 audit marker exceeds byte bound")
    temporary = D1_AUDIT_MARKER_PATH.with_suffix(".tmp")
    with open(temporary, "wb") as handle:
        handle.write(wire)
    os.replace(temporary, D1_AUDIT_MARKER_PATH)
    return sha(wire)

class Handler(BaseHTTPRequestHandler):
    server_version = "ARGUS-D0A-WAS/1"
    def log_message(self, fmt, *args): print(fmt % args, file=sys.stderr)
    def send_json(self, status, value):
        wire=json.dumps(value,separators=(",",":"),sort_keys=True).encode()
        if len(wire) > MAX_BYTES: raise ValueError("response exceeds 32 KiB")
        self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(wire))); self.end_headers(); self.wfile.write(wire)
    def do_GET(self):
        if self.path == "/health":
            return self.send_json(200, {"service":"was", "status":"ok"})
        if self.path == "/d1/observe":
            return self.d1_observe()
        self.send_json(404, {"service":"was", "status":"not_found"})
    def do_POST(self):
        if self.headers.get("X-ARGUS-Internal-Caller") != "web-d0a": return self.send_json(403,{"error":"internal_web_only"})
        try: length=int(self.headers.get("Content-Length","0"))
        except ValueError: length=0
        try: data=json.loads(self.rfile.read(length)) if 0<length<=MAX_BYTES else None
        except (UnicodeDecodeError,json.JSONDecodeError): data=None
        if not data or not valid_run_id(data.get("run_id")) or not manifest_approved(data["run_id"]): return self.send_json(400,{"error":"approved_run_manifest_required"})
        if self.path=="/fixed-auth": return self.auth(data)
        if self.path=="/fixed-marker": return self.marker(data)
        self.send_json(404,{"error":"not_found"})
    def auth(self,data):
        if data.get("fixture_id")!=AUTH_FIXTURE or data.get("probe")!="fixture-token-v1": return self.send_json(403,{"error":"fixture_not_allowed"})
        try: account=synthetic_auth()
        except mysql.connector.Error as exc: return self.send_json(503,{"error":"synthetic_db_unavailable","detail":exc.__class__.__name__})
        if account!={"username":"synthetic_admin","role":"administrator"}: return self.send_json(500,{"error":"unexpected_synthetic_auth_result"})
        decision=sha(json.dumps({"run_id":data["run_id"],"request_id":data["request_id"],"principal":"synthetic_admin","fixture":AUTH_FIXTURE},sort_keys=True,separators=(",",":")).encode())
        envelope={"schema_version":"argus.hybridnb-envelope/v1","request_id":data["request_id"],"run_id":data["run_id"],"source":"original_request","method":"POST","path":"/auth","body_sha256":data["original_request_sha256"],"evaluation_status":"disabled_not_evaluated"}
        append_event(data["run_id"],"S02",1,"fixed_sqli_auth_fixture",data["request_id"],"accepted",fixture_id=AUTH_FIXTURE,content_sha256=data["original_request_sha256"],original_request_envelope=envelope,correlation={"principal":"synthetic_admin","auth_decision_hash":decision})
        append_event(data["run_id"],"S02",2,"hybridnb_adapter",data["request_id"],"not_evaluated",fixture_id=AUTH_FIXTURE,content_sha256=data["original_request_sha256"],original_request_envelope=envelope,correlation={"adapter":"disabled_not_evaluated","crs_fields_consumed":False})
        self.send_json(200,{"auth_decision_hash":decision})
    def marker(self,data):
        required=(data.get("fixture_id")==MARKER_FIXTURE and data.get("action")=="write_fixed_marker" and self.headers.get("X-ARGUS-Session")==session_token(data["run_id"]))
        if not required: return self.send_json(401,{"error":"administrator_session_required"})
        marker={"marker_schema_version":"argus.fixed-marker/v1","run_id":data["run_id"],"request_id":data["request_id"],"fixture_id":MARKER_FIXTURE,"operation":"write_fixed_marker","timestamp_utc":now(),"non_destructive":True,"auth_decision_hash":data["auth_decision_hash"],"admin_session_hash":data["admin_session_hash"],"upload_ticket_id":data["upload_ticket_id"],"web_action_context_id":data["web_action_context_id"]}
        wire=json.dumps(marker,separators=(",",":"),sort_keys=True).encode(); marker_sha=sha(wire)
        try:
            with open(EVIDENCE_ROOT/data["run_id"]/"marker.json", "xb") as handle: handle.write(wire)
        except FileExistsError: return self.send_json(409,{"error":"marker_already_written"})
        event=append_event(data["run_id"],"S04",4,"fixed_marker_written",data["request_id"],"written",fixture_id=MARKER_FIXTURE,content_sha256=marker_sha,response_sha256=marker_sha,correlation={"web_marker_sha256":marker_sha,"web_action_context_id":data["web_action_context_id"],"auth_decision_hash":data["auth_decision_hash"],"admin_session_hash":data["admin_session_hash"],"upload_ticket_id":data["upload_ticket_id"],"non_destructive":True})
        self.send_json(200,{"evidence_id":event["evidence_id"],"web_marker_sha256":marker_sha,"operation":"write_fixed_marker"})
    def d1_observe(self):
        run_id, request_id = self.headers.get("X-ARGUS-Run-Id", ""), self.headers.get("X-ARGUS-Request-Id", "")
        if self.headers.get("X-ARGUS-Internal-Caller") != "web-d1":
            return self.send_json(403, {"error":"internal_web_only"})
        if not valid_base_run_id(run_id) or not re.fullmatch(r"[A-Za-z0-9._-]{8,128}", request_id) or self.headers.get("X-ARGUS-Fixture-Id") != D1_FIXTURE:
            return self.send_json(400, {"error":"invalid_benign_d1_request"})
        try:
            aws_observation = json.loads(self.headers.get("X-ARGUS-D1-Aws-Observation", ""))
        except json.JSONDecodeError:
            aws_observation = None
        expected_aws_keys = {"s3_version_id", "s3_content_sha256", "ssm_parameter_name_sha256"}
        if not isinstance(aws_observation, dict) or set(aws_observation) != expected_aws_keys or not re.fullmatch(r"[a-f0-9]{64}", aws_observation["s3_content_sha256"]) or not re.fullmatch(r"[a-f0-9]{64}", aws_observation["ssm_parameter_name_sha256"]):
            return self.send_json(400, {"error":"exact_aws_observation_required"})
        if not D1_LOCK.acquire(blocking=False):
            return self.send_json(429, {"error":"d1_concurrency_limited"})
        try:
            if not d1_rate_allowed():
                return self.send_json(429, {"error":"d1_rate_limited"})
            query_id = str(uuid.uuid4())
            try:
                rows = d1_synthetic_select(request_id, query_id)
                marker_sha = write_d1_audit_marker(run_id, request_id, query_id)
                d1_source_log("d1_synthetic_select", run_id=run_id, request_id=request_id, fixture_id=D1_FIXTURE,
                    service_request_id="was-d1-" + query_id, query_id=query_id, row_count=len(rows), audit_marker_path=str(D1_AUDIT_MARKER_PATH), audit_marker_sha256=marker_sha,
                    s3_version_id=aws_observation["s3_version_id"], hybridnb_status="disabled_not_evaluated", waf_status="disabled_not_evaluated")
            except (OSError, ValueError, mysql.connector.Error) as exc:
                structured_log("d1_observe_failed", run_id=run_id, request_id=request_id, fixture_id=D1_FIXTURE, query_id=query_id, error_class=exc.__class__.__name__)
                return self.send_json(503, {"error":"d1_synthetic_observation_unavailable"})
            self.send_json(200, {"fixture_id":D1_FIXTURE, "query_id":query_id, "row_count":len(rows),
                "row_set_sha256":sha(json.dumps(rows, separators=(",", ":"), sort_keys=True).encode()), "audit_marker_sha256":marker_sha})
        finally:
            D1_LOCK.release()
if __name__ == "__main__": ThreadingHTTPServer(("0.0.0.0",8081),Handler).serve_forever()
