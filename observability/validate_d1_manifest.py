"""Stdlib-only D1 v2 validation with source-native raw-evidence correlation."""
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

RUN_RE = re.compile(r"^ARGUS-[0-9]{8}-BASE-R[0-9]{2}$")
BEN_RE = re.compile(r"^BEN-[A-Z0-9-]+$")
SHA_RE = re.compile(r"^[a-f0-9]{64}$")
REQUIRED_SOURCES = ("alb", "nginx_modsecurity", "d0_envelope", "web", "was", "host", "flow_logs", "cloudtrail", "s3_getobject", "rds")
MAX_EXPORTED_RAW_BYTES = 1048576
MAX_WINDOW_SECONDS = 900
EVIDENCE_KINDS = {"alb":"alb_access_log", "nginx_modsecurity":"nginx_modsecurity_log", "d0_envelope":"hybridnb_envelope_v1", "web":"web_application_log", "was":"was_application_log", "host":"host_audit_log", "flow_logs":"vpc_flow_log", "cloudtrail":"cloudtrail_management_event", "s3_getobject":"cloudtrail_s3_data_event", "rds":"rds_database_log"}
ANCHOR_KEYS = {"alb":("trace_id","request_anchor","path"), "nginx_modsecurity":("run_id","request_id","transaction_id"), "d0_envelope":("run_id","request_id","body_sha256"), "web":("run_id","request_id","session_hash"), "was":("run_id","request_id","service_request_id","query_id"), "host":("host_id","process","pid","audit_epoch","audit_serial"), "flow_logs":("eni_id","srcaddr","dstaddr","srcport","dstport","protocol","start_epoch","end_epoch"), "cloudtrail":("event_id","aws_request_id","event_name","parameter_name","principal"), "s3_getobject":("event_id","aws_request_id","event_name","bucket","key","version_id","principal"), "rds":("connection_id","query_id")}
SOURCE_MARKERS = {"alb":(), "nginx_modsecurity":("nginx","modsecurity"), "d0_envelope":("argus.hybridnb-envelope/v1","disabled_not_evaluated"), "web":("d1_observe_completed","web"), "was":("d1_synthetic_select","was"), "host":("audit(",), "flow_logs":("eni-",), "cloudtrail":("eventID","GetParameter","ssm.amazonaws.com"), "s3_getobject":("GetObject","s3.amazonaws.com"), "rds":("argus_d1_query_id=",)}

def fail(message): raise ValueError(message)
def utc(value, label):
    if not isinstance(value, str) or not value.endswith("Z"): fail(label + " must be a UTC Z timestamp")
    try: parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc: raise ValueError(label + " is not parseable") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed): fail(label + " is not UTC")
    return parsed
def load(path):
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc: raise ValueError("manifest is not valid JSON") from exc
def manifest_sha256(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def validate_window(window):
    if not isinstance(window, dict) or set(window) != {"start_utc", "end_utc"}: fail("run window contract mismatch")
    start, end = utc(window["start_utc"], "run window start"), utc(window["end_utc"], "run window end")
    seconds = (end - start).total_seconds()
    if not 0 < seconds <= MAX_WINDOW_SECONDS: fail("run window must be positive and bounded")
    return start, end

def validate_anchors(source, anchors, run_id, application_request_id, event_time, window_start, window_end):
    if not isinstance(anchors, dict) or set(anchors) != set(ANCHOR_KEYS[source]): fail("source-native anchor fields mismatch")
    if any(not isinstance(value, (str, int)) or value == "" for value in anchors.values()): fail("source-native anchor value invalid")
    if source in ("nginx_modsecurity", "d0_envelope", "web", "was"):
        if anchors["run_id"] != run_id or anchors["request_id"] != application_request_id: fail("application source correlation mismatch")
    if source == "web" and not SHA_RE.fullmatch(anchors["session_hash"]): fail("web D1 session hash invalid")
    if source == "d0_envelope" and not SHA_RE.fullmatch(anchors["body_sha256"]): fail("D0 body hash invalid")
    if source == "alb":
        if not str(anchors["trace_id"]).startswith("Root=") or not str(anchors["request_anchor"]).startswith("GET ") or not str(anchors["path"]).startswith("/"): fail("ALB native anchors invalid")
    if source == "flow_logs":
        try:
            ipaddress.ip_address(str(anchors["srcaddr"])); ipaddress.ip_address(str(anchors["dstaddr"]))
            ports_and_protocol = [int(anchors[x]) for x in ("srcport","dstport","protocol")]
            flow_start, flow_end = int(anchors["start_epoch"]), int(anchors["end_epoch"])
        except ValueError as exc: raise ValueError("flow tuple anchors invalid") from exc
        if not str(anchors["eni_id"]).startswith("eni-") or not 0 < ports_and_protocol[0] <= 65535 or not 0 < ports_and_protocol[1] <= 65535 or not 0 < ports_and_protocol[2] <= 255: fail("flow tuple anchors invalid")
        if flow_start > flow_end or flow_start < int(window_start.timestamp()) or flow_end > int(window_end.timestamp()) or not flow_start <= int(event_time.timestamp()) <= flow_end: fail("flow native time anchors outside run window")
    if source == "cloudtrail":
        if anchors["event_name"] != "GetParameter" or not str(anchors["parameter_name"]).startswith("/") or not str(anchors["principal"]).startswith("arn:"): fail("CloudTrail SSM GetParameter anchors invalid")
    if source == "s3_getobject":
        if anchors["event_name"] != "GetObject" or not str(anchors["bucket"]) or not str(anchors["key"]) or not str(anchors["version_id"]) or not str(anchors["principal"]).startswith("arn:"): fail("S3 GetObject anchors invalid")
    if source == "host":
        try: audit_epoch, audit_serial = int(anchors["audit_epoch"]), int(anchors["audit_serial"])
        except ValueError as exc: raise ValueError("host audit anchors invalid") from exc
        if not str(anchors["pid"]).isdigit() or audit_serial < 0 or audit_epoch < int(window_start.timestamp()) or audit_epoch > int(window_end.timestamp()) or abs(audit_epoch - int(event_time.timestamp())) > 1: fail("host audit anchors invalid")
    if source in ("was", "rds") and not str(anchors["query_id"]): fail("WAS/RDS query anchor invalid")
    if source == "was" and not str(anchors["service_request_id"]).startswith("was-d1-"): fail("WAS service request anchor invalid")
    if source == "rds" and not str(anchors["connection_id"]).isdigit(): fail("RDS database anchors invalid")

def exported_raw(root, relative_path, source, event_time, anchors):
    if not isinstance(relative_path, str) or not relative_path or Path(relative_path).is_absolute(): fail("runtime evidence path must be a relative path")
    path = (root / relative_path).resolve()
    try: path.relative_to(root)
    except ValueError as exc: raise ValueError("runtime evidence path escapes evidence root") from exc
    try: raw = path.read_bytes()
    except OSError as exc: raise ValueError("runtime exported raw evidence is missing") from exc
    if not raw or len(raw) > MAX_EXPORTED_RAW_BYTES: fail("runtime exported raw evidence is empty or exceeds the bound")
    try: text = raw.decode("utf-8")
    except UnicodeDecodeError as exc: raise ValueError("runtime exported raw evidence must be UTF-8") from exc
    native_time_marker = ()
    for marker in (*native_time_marker, *SOURCE_MARKERS[source], *(str(value) for value in anchors.values())):
        if marker not in text: fail("runtime raw evidence lacks native time/anchor/semantic marker")
    return path, raw

def validate(manifest, evidence_root=None):
    exact = {"schema_version","run_id","fixture_id","proof_kind","run_window","application_request_id","planned_sources","records"}
    if not isinstance(manifest, dict) or set(manifest) != exact or manifest.get("schema_version") != "argus.d1-evidence-manifest/v2": fail("manifest version/fields mismatch")
    run_id, fixture = manifest.get("run_id"), manifest.get("fixture_id")
    application_request_id = manifest.get("application_request_id")
    if not RUN_RE.fullmatch(run_id or "") or not BEN_RE.fullmatch(fixture or "") or not isinstance(application_request_id, str) or not 8 <= len(application_request_id) <= 128: fail("run ID, benign fixture, or application request ID invalid")
    start, end = validate_window(manifest["run_window"])
    if tuple(manifest.get("planned_sources", [])) != REQUIRED_SOURCES: fail("planned source set/order mismatch")
    if manifest["proof_kind"] == "plan":
        if manifest["records"] != []: fail("plan proof must not claim runtime records")
        return {"proof_kind":"plan", "runtime_proven":False}
    if manifest["proof_kind"] != "runtime" or not isinstance(manifest["records"], list) or len(manifest["records"]) != len(REQUIRED_SOURCES): fail("runtime proof requires every source record")
    if evidence_root is None: fail("runtime proof requires task-local exported evidence root")
    root = Path(evidence_root).resolve()
    if not root.is_dir(): fail("runtime evidence root is not a directory")
    sources, paths = set(), set()
    for record in manifest["records"]:
        required = {"source","event_time_utc","evidence_path","content_sha256","collector","redaction_status","evidence_kind","anchors"}
        if not isinstance(record, dict): fail("runtime record fields mismatch")
        if record.get("source") == "s3_getobject": required.add("scope")
        if set(record) != required: fail("runtime record fields mismatch")
        source = record.get("source")
        if source not in REQUIRED_SOURCES or source in sources: fail("runtime source missing or duplicated")
        sources.add(source)
        event_time = utc(record.get("event_time_utc"), "runtime event time")
        if not start <= event_time <= end: fail("runtime event is outside bounded run window")
        if not SHA_RE.fullmatch(record.get("content_sha256", "")) or not isinstance(record.get("collector"), str) or not record["collector"] or not isinstance(record.get("redaction_status"), str) or not record["redaction_status"]: fail("runtime hash/collector/redaction invalid")
        if record.get("evidence_kind") != EVIDENCE_KINDS[source]: fail("runtime evidence kind mismatch")
        if source == "d0_envelope" and record["redaction_status"] != "disabled_not_evaluated": fail("D0 envelope must remain D5-disabled")
        if source == "s3_getobject" and record.get("scope") != "scoped_getobject": fail("S3 evidence is not scoped GetObject")
        validate_anchors(source, record["anchors"], run_id, application_request_id, event_time, start, end)
        path, raw = exported_raw(root, record["evidence_path"], source, record["event_time_utc"], record["anchors"])
        if path in paths: fail("runtime exported raw evidence path is reused")
        paths.add(path)
        if hashlib.sha256(raw).hexdigest() != record["content_sha256"]: fail("runtime exported raw evidence hash mismatch")
    if sources != set(REQUIRED_SOURCES): fail("runtime source coverage mismatch")
    return {"proof_kind":"runtime", "runtime_proven":True}
