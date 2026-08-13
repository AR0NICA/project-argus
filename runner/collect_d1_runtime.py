"""Collect one real, benign D1 runtime observation through the AWS CLI.

This module deliberately has no boto dependency.  It writes a runtime manifest
only after each native source was fetched, reduced to one matching record, and
validated.  It never creates AWS resources or uploads evidence.
"""
import argparse
import datetime as dt
import gzip
import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observability"))
from validate_d1_manifest import EVIDENCE_KINDS, REQUIRED_SOURCES, validate  # noqa: E402

FIXTURE_ID = "BEN-D1-OBS-001"
APPROVED_HOSTNAME = "argus-base.ar0nica.xyz"
MAX_RAW_BYTES = 1048576
RUN_RE = re.compile(r"^ARGUS-[0-9]{8}-BASE-R[0-9]{2}$")
TRACE_RE = re.compile(r"^Root=1-[0-9a-f]{8}-[0-9a-f]{24}$")


class CollectorError(RuntimeError):
    pass


class NoNativeMatch(CollectorError):
    """A source has not delivered the requested record yet; safe to poll."""
    pass


def utc_now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def utc_text(value):
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value, label):
    if not isinstance(value, str):
        raise CollectorError(label + " must be a UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00") if value.endswith("Z") else dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise CollectorError(label + " is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise CollectorError(label + " is not UTC")
    return parsed


def terraform_values(path):
    """Read the exact JSON shape emitted by ``terraform output -json``."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorError("terraform output JSON cannot be read") from exc
    if not isinstance(document, dict):
        raise CollectorError("terraform output JSON is not an object")
    values = {}
    for name, item in document.items():
        if not isinstance(item, dict) or set(item) != {"sensitive", "type", "value"}:
            raise CollectorError("terraform output JSON has an invalid output entry")
        values[name] = item["value"]
    return values


def collector_config(values, args):
    try:
        targets = values["collector_targets"]
        groups = targets["source_log_groups"]
        alb_bucket = targets["alb_access_log_bucket"]
        rds_groups = targets["rds_native_log_groups"]
        rds_general = next(group for group in rds_groups if isinstance(group, str) and group.endswith("/general"))
        source_groups = {source: groups[name] for source, name in {
            "nginx_modsecurity": "nginx_modsecurity", "d0_envelope": "d0_envelope", "web": "web",
            "was": "was", "host": "host", "flow_logs": "vpc_flow", "cloudtrail": "cloudtrail",
            "s3_getobject": "cloudtrail"}.items()}
    except (KeyError, StopIteration, TypeError) as exc:
        raise CollectorError("terraform output collector_targets does not expose all D1 collection locations") from exc
    if not all(isinstance(value, str) and value for value in (*source_groups.values(), alb_bucket, rds_general)):
        raise CollectorError("terraform outputs contain an empty D1 collection location")
    if not isinstance(values.get("alb_dns_name"), str) or not values["alb_dns_name"]:
        raise CollectorError("terraform output alb_dns_name is required")
    if values.get("base_hostname") != args.hostname:
        raise CollectorError("terraform output base_hostname does not match the approved collector hostname")
    return {"alb_dns_name": values["alb_dns_name"], "alb_bucket": alb_bucket,
            "alb_prefix": "alb/AWSLogs/" + args.account_id + "/elasticloadbalancing/" + args.region + "/",
            "groups": source_groups, "rds_general": rds_general}


def run_aws(args, command):
    executable = shutil.which("aws")
    if executable is None:
        raise CollectorError("AWS CLI is not on PATH")
    base = [executable, "--no-cli-pager", "--region", args.region]
    if args.aws_profile:
        base.extend(["--profile", args.aws_profile])
    completed = subprocess.run(base + command, capture_output=True, text=True, encoding="utf-8", timeout=args.cli_timeout_seconds)
    if completed.returncode != 0:
        raise CollectorError("AWS CLI failed for " + command[0])
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise CollectorError("AWS CLI did not return JSON for " + command[0]) from exc


def one_https_request(args):
    if not RUN_RE.fullmatch(args.run_id) or not args.request_id.startswith(args.run_id + "-") or not TRACE_RE.fullmatch(args.trace_id):
        raise CollectorError("BASE run, request, or trace ID is invalid")
    try:
        interface = ipaddress.ip_interface(args.client_cidr)
        if interface.version != 4 or interface.network.prefixlen != 32 or not interface.ip.is_global:
            raise ValueError
    except ValueError as exc:
        raise CollectorError("runtime client CIDR must be supplied as a public IPv4 /32 address") from exc
    args.client_ipv4 = str(interface.ip)
    url = "https://" + args.hostname + args.path
    request = urllib.request.Request(url, method="GET", headers={
        "Host": args.hostname, "X-ARGUS-Run-Id": args.run_id,
        "X-ARGUS-Request-Id": args.request_id, "X-ARGUS-Fixture-Id": FIXTURE_ID, "X-Amzn-Trace-Id": args.trace_id,
        "User-Agent": "ARGUS-D1-BEN-D1-OBS-001/1",
    })
    try:
        with urllib.request.urlopen(request, timeout=args.request_timeout_seconds) as response:
            if response.status != 200:
                raise CollectorError("benign HTTPS request did not return exact 200")
            if response.headers.get_content_type() != "application/json":
                raise CollectorError("benign HTTPS response is not JSON")
            raw = response.read(MAX_RAW_BYTES + 1)
            if len(raw) > MAX_RAW_BYTES:
                raise CollectorError("benign HTTPS JSON response exceeds the bounded contract")
            try:
                document = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CollectorError("benign HTTPS response JSON is invalid") from exc
            expected = {"fixture_id": FIXTURE_ID, "run_id": args.run_id, "request_id": args.request_id,
                        "waf_status": "disabled_not_evaluated", "hybridnb_status": "disabled_not_evaluated"}
            if not isinstance(document, dict) or any(document.get(key) != value for key, value in expected.items()):
                raise CollectorError("benign HTTPS response does not confirm the exact D1 run/request/fixture/status contract")
            if not isinstance(document.get("row_count"), int) or not 0 <= document["row_count"] <= 10:
                raise CollectorError("benign HTTPS response violates the bounded synthetic-row contract")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CollectorError("exactly one benign HTTPS request failed") from exc


def select_one(items, predicate, source):
    matches = [item for item in items if predicate(item)]
    if not matches:
        raise NoNativeMatch(source + " has not delivered a matching native record")
    if len(matches) != 1:
        raise CollectorError(source + " must contain exactly one matching native record")
    return matches[0]


def cloudwatch_events(args, group, start, end):
    events, token = [], None
    while True:
        command = ["logs", "filter-log-events", "--log-group-name", group,
            "--start-time", str(int(start.timestamp() * 1000)), "--end-time", str(int(end.timestamp() * 1000)), "--output", "json"]
        if token:
            command.extend(["--next-token", token])
        response = run_aws(args, command)
        page = response.get("events")
        if not isinstance(page, list):
            raise CollectorError("CloudWatch response lacks events")
        events.extend(page)
        next_token = response.get("nextToken")
        if next_token is None:
            return events
        if not isinstance(next_token, str) or not next_token or next_token == token:
            raise CollectorError("CloudWatch pagination token is invalid")
        token = next_token


def json_message(event, source):
    if not isinstance(event, dict) or not isinstance(event.get("message"), str):
        raise CollectorError(source + " CloudWatch event has no text message")
    try:
        value = json.loads(event["message"])
    except json.JSONDecodeError as exc:
        raise CollectorError(source + " native message is not JSON") from exc
    if not isinstance(value, dict):
        raise CollectorError(source + " native message is not an object")
    return value


def message_time(document, source):
    for field in ("event_time_utc", "timestamp", "eventTime", "time"):
        if field in document:
            return parse_utc(document[field], source + " event time")
    raise CollectorError(source + " native message lacks a UTC event time")


def app_record(args, source, events, start, end):
    decoded = []
    for event in events:
        try:
            document = json_message(event, source)
        except CollectorError:
            if source == "nginx_modsecurity":
                continue
            raise
        decoded.append((event, document))
    def matches(pair):
        document = pair[1]
        if document.get("run_id") != args.run_id or document.get("request_id") != args.request_id:
            return False
        if source == "nginx_modsecurity":
            return document.get("service") == "nginx modsecurity" and isinstance(document.get("transaction_id"), str) and document["transaction_id"]
        return document.get("source") == source
    event, document = select_one(decoded, matches, source)
    when = message_time(document, source)
    if not start <= when <= end:
        raise CollectorError(source + " native event is outside the run window")
    if source == "nginx_modsecurity":
        anchors = {"run_id": args.run_id, "request_id": args.request_id, "transaction_id": document.get("transaction_id")}
    elif source == "d0_envelope":
        anchors = {"run_id": args.run_id, "request_id": args.request_id, "body_sha256": document.get("body_sha256")}
    elif source == "web":
        anchors = {"run_id": args.run_id, "request_id": args.request_id, "session_hash": document.get("session_hash")}
    else:
        anchors = {"run_id": args.run_id, "request_id": args.request_id, "service_request_id": document.get("service_request_id"), "query_id": document.get("query_id")}
    return when, anchors, event["message"].encode("utf-8")


def cloudtrail_record(args, source, events, start, end):
    decoded = [(event, json_message(event, source)) for event in events]
    if source == "cloudtrail":
        event, document = select_one(decoded, lambda pair: pair[1].get("eventSource") == "ssm.amazonaws.com" and pair[1].get("eventName") == "GetParameter" and pair[1].get("requestParameters", {}).get("name") == args.ssm_parameter_name, source)
        identity = document.get("userIdentity", {})
        principal = identity.get("sessionContext", {}).get("sessionIssuer", {}).get("arn") or identity.get("arn")
        anchors = {"event_id": document.get("eventID"), "aws_request_id": document.get("requestID"), "event_name": "GetParameter", "parameter_name": args.ssm_parameter_name, "principal": principal}
    else:
        def is_target(pair):
            document = pair[1]
            parameters = document.get("requestParameters", {})
            return document.get("eventSource") == "s3.amazonaws.com" and document.get("eventName") == "GetObject" and parameters.get("bucketName") == args.canary_bucket and parameters.get("key") == args.canary_object_key and parameters.get("versionId") == args.canary_object_version_id
        event, document = select_one(decoded, is_target, source)
        identity = document.get("userIdentity", {})
        principal = identity.get("sessionContext", {}).get("sessionIssuer", {}).get("arn") or identity.get("arn")
        anchors = {"event_id": document.get("eventID"), "aws_request_id": document.get("requestID"), "event_name": "GetObject", "bucket": args.canary_bucket, "key": args.canary_object_key, "version_id": args.canary_object_version_id, "principal": principal}
    when = message_time(document, source)
    if not start <= when <= end:
        raise CollectorError(source + " native event is outside the run window")
    return when, anchors, event["message"].encode("utf-8")


def parse_audit_line(text, start, end):
    match = re.search(r"audit\((\d+)\.\d+:(\d+)\).*?pid=(\d+).*?comm=\"([^\"]+)\"", text)
    host = re.search(r"(?:host_id|node)=([^\s]+)", text)
    if not match or not host:
        raise CollectorError("host auditd record has no native anchors")
    when = dt.datetime.fromtimestamp(int(match.group(1)), tz=dt.timezone.utc)
    if not start <= when <= end:
        raise CollectorError("host auditd event is outside the run window")
    return when, {"host_id": host.group(1), "process": match.group(4), "pid": int(match.group(3)), "audit_epoch": int(match.group(1)), "audit_serial": int(match.group(2))}


def parse_flow_line(text, start, end):
    fields = text.split()
    if len(fields) < 14:
        raise CollectorError("VPC flow record has too few fields")
    try:
        anchors = {"eni_id": fields[2], "srcaddr": fields[3], "dstaddr": fields[4], "srcport": int(fields[5]), "dstport": int(fields[6]), "protocol": int(fields[7]), "start_epoch": int(fields[10]), "end_epoch": int(fields[11])}
    except ValueError as exc:
        raise CollectorError("VPC flow record has invalid tuple fields") from exc
    when = dt.datetime.fromtimestamp(anchors["start_epoch"], tz=dt.timezone.utc)
    if not start <= when <= end or anchors["start_epoch"] > anchors["end_epoch"]:
        raise CollectorError("VPC flow event is outside the run window")
    return when, anchors


def cw_text_record(args, source, events, start, end):
    if source == "host":
        event = select_one(events, lambda item: "audit(" in item.get("message", "") and "SYSCALL=rename" in item.get("message", "") and ("host_id=" + args.host_id in item.get("message", "") or "node=" + args.host_id in item.get("message", "")) and ("comm=\"" + args.host_process + "\"" in item.get("message", "")), source)
        when, anchors = parse_audit_line(event["message"], start, end)
    else:
        candidates = []
        for event in events:
            try:
                when, anchors = parse_flow_line(event.get("message", ""), start, end)
            except CollectorError:
                continue
            if anchors["eni_id"] == args.flow_eni_id and anchors["srcaddr"] == args.flow_srcaddr and anchors["dstaddr"] == args.flow_dstaddr and anchors["dstport"] == args.flow_dstport and anchors["protocol"] == 6:
                candidates.append({"event": event, "when": when, "anchors": anchors})
        selected = select_one(candidates, lambda item: True, source)
        event = selected["event"]
        when = selected["when"]
        anchors = selected["anchors"]
    return when, anchors, event["message"].encode("utf-8")


def alb_record(args, config, start, end):
    lines = []
    for day in {start.date(), end.date()}:
        token = None
        while True:
            prefix = config["alb_prefix"] + day.strftime("%Y/%m/%d/")
            command = ["s3api", "list-objects-v2", "--bucket", config["alb_bucket"], "--prefix", prefix, "--output", "json"]
            if token:
                command.extend(["--continuation-token", token])
            response = run_aws(args, command)
            contents = response.get("Contents")
            if not isinstance(contents, list):
                raise CollectorError("ALB S3 listing lacks objects")
            for item in contents:
                key = item.get("Key") if isinstance(item, dict) else None
                modified = item.get("LastModified") if isinstance(item, dict) else None
                if not isinstance(key, str) or not key.endswith(".gz") or not isinstance(modified, str):
                    continue
                if parse_utc(modified, "ALB object LastModified") < start:
                    continue
                temporary = Path(args.output_root) / (".d1-alb-" + uuid.uuid4().hex + ".gz")
                run_aws(args, ["s3api", "get-object", "--bucket", config["alb_bucket"], "--key", key, str(temporary)])
                try:
                    text = gzip.decompress(temporary.read_bytes()).decode("utf-8")
                except (OSError, UnicodeDecodeError) as exc:
                    raise CollectorError("ALB S3 object is not a UTF-8 gzip log") from exc
                finally:
                    temporary.unlink(missing_ok=True)
                lines.extend(line for line in text.splitlines() if args.trace_id in line)
            if not response.get("IsTruncated", False):
                break
            next_token = response.get("NextContinuationToken")
            if not isinstance(next_token, str) or not next_token or next_token == token:
                raise CollectorError("ALB S3 pagination token is invalid")
            token = next_token
    line = select_one(lines, lambda item: args.trace_id in item, "alb")
    fields = re.findall(r'"[^\"]*"|\S+', line)
    if len(fields) < 13:
        raise CollectorError("ALB native line has too few fields")
    when = parse_utc(fields[1], "ALB event time")
    if not start <= when <= end:
        raise CollectorError("ALB native event is outside the run window")
    request = fields[12].strip('"').split()
    if len(request) < 2 or urlparse(request[1]).path != args.path:
        raise CollectorError("ALB native request does not match the one benign request")
    if fields[3].rsplit(":", 1)[0] != args.client_ipv4:
        raise CollectorError("ALB native client address is not the execution-time public IPv4 /32")
    return when, {"trace_id": args.trace_id, "request_anchor": fields[12].strip('"'), "path": args.path}, (line + "\n").encode("utf-8")


def rds_record(args, events, start, end, expected_query_id):
    event = select_one(events, lambda item: "argus_d1_query_id=" + expected_query_id in item.get("message", ""), "rds")
    text = event["message"]
    match = re.search(r"^(\d{4}-\d{2}-\d{2}T[^\s]+|\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\d+)\s+Query\s+.*?/\*\s*argus_d1_query_id=([a-f0-9-]{36})\b", text, re.DOTALL)
    if not match or match.group(3) != expected_query_id:
        raise CollectorError("RDS general native record does not contain the exact WAS query anchor")
    timestamp = match.group(1).replace(" ", "T", 1)
    if not timestamp.endswith("Z") and not re.search(r"[+-]\d{2}:\d{2}$", timestamp):
        timestamp += "Z"
    when = parse_utc(timestamp, "rds event time")
    anchors = {"connection_id": int(match.group(2)), "query_id": match.group(3)}
    if not start <= when <= end:
        raise CollectorError("RDS general event is outside the run window")
    return when, anchors, text.encode("utf-8")


def secure_directory(path):
    path.mkdir(parents=True, exist_ok=False)
    os.chmod(path, 0o700)
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise CollectorError("raw evidence directory permission is not restricted")


def write_raw(root, source, raw):
    if not raw or len(raw) > MAX_RAW_BYTES:
        raise CollectorError(source + " raw export is empty or exceeds 1 MiB")
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CollectorError(source + " raw export is not UTF-8") from exc
    path = root / (source + ".raw")
    if path.exists():
        raise CollectorError("refusing to reuse a raw evidence path")
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    return path.name, hashlib.sha256(raw).hexdigest()


def poll(args, predicate, not_after=None):
    deadline = time.monotonic() + args.poll_timeout_seconds
    if not_after is not None:
        deadline = min(deadline, not_after)
    while True:
        try:
            result = predicate()
        except NoNativeMatch:
            result = None
        if result is not None:
            return result
        if time.monotonic() >= deadline:
            raise CollectorError("bounded evidence polling timed out")
        time.sleep(args.poll_interval_seconds)


def collect(args):
    if args.fixture_id != FIXTURE_ID or args.concurrency != 1 or args.minimum_interval_seconds != 1:
        raise CollectorError("collector is fixed to one BEN-D1-OBS-001 request at 1 rps and concurrency 1")
    if not 1 <= args.poll_interval_seconds <= 60 or not 1 <= args.poll_timeout_seconds <= 900 or not 1 <= args.cli_timeout_seconds <= 120:
        raise CollectorError("polling or CLI timeout is outside the bounded contract")
    if args.hostname != APPROVED_HOSTNAME:
        raise CollectorError("collector hostname must be " + APPROVED_HOSTNAME)
    if args.path != "/d1/observe":
        raise CollectorError("collector request path must be /d1/observe")
    run_directory = Path(args.output_root).resolve() / args.run_id
    if run_directory.exists():
        raise CollectorError("refusing to overwrite or append a D1 run directory")
    key = Path(args.redaction_key_file).read_bytes()
    if not key:
        raise CollectorError("HMAC redaction key is empty")
    config = collector_config(terraform_values(args.terraform_output_json), args)
    run_directory.mkdir(parents=True)
    raw_root = run_directory / "raw"
    secure_directory(raw_root)
    start = utc_now()
    collection_deadline = time.monotonic() + 900
    one_https_request(args)
    records = []
    def collect(source, getter):
        when, anchors, raw = poll(args, getter, collection_deadline)
        name, digest = write_raw(raw_root, source, raw)
        record = {"source": source, "event_time_utc": utc_text(when), "evidence_path": name, "content_sha256": digest,
                  "collector": "argus-d1-aws-cli", "redaction_status": "disabled_not_evaluated" if source == "d0_envelope" else "restricted_raw",
                  "evidence_kind": EVIDENCE_KINDS[source], "anchors": anchors}
        if source == "s3_getobject": record["scope"] = "scoped_getobject"
        records.append(record)
    collect("alb", lambda: alb_record(args, config, start, utc_now()))
    for source in ("nginx_modsecurity", "d0_envelope", "web", "was"):
        collect(source, lambda source=source: app_record(args, source, cloudwatch_events(args, config["groups"][source], start, utc_now()), start, utc_now()))
    collect("host", lambda: cw_text_record(args, "host", cloudwatch_events(args, config["groups"]["host"], start, utc_now()), start, utc_now()))
    collect("flow_logs", lambda: cw_text_record(args, "flow_logs", cloudwatch_events(args, config["groups"]["flow_logs"], start, utc_now()), start, utc_now()))
    for source in ("cloudtrail", "s3_getobject"):
        collect(source, lambda source=source: cloudtrail_record(args, source, cloudwatch_events(args, config["groups"][source], start, utc_now()), start, utc_now()))
    was_query_id = next(record["anchors"]["query_id"] for record in records if record["source"] == "was")
    collect("rds", lambda: rds_record(args, cloudwatch_events(args, config["rds_general"], start, utc_now()), start, utc_now(), was_query_id))
    end = utc_now()
    manifest = {"schema_version": "argus.d1-evidence-manifest/v2", "run_id": args.run_id, "fixture_id": FIXTURE_ID,
                "proof_kind": "runtime", "run_window": {"start_utc": utc_text(start), "end_utc": utc_text(end)},
                "application_request_id": args.request_id, "planned_sources": list(REQUIRED_SOURCES), "records": records}
    validate(manifest, raw_root)
    review = {"schema_version": "argus.d1-review/v1", "run_id": args.run_id, "fixture_id": FIXTURE_ID,
              "records": [{"source": record["source"], "raw_hmac_sha256": hmac.new(key, (raw_root / record["evidence_path"]).read_bytes(), hashlib.sha256).hexdigest()} for record in records]}
    audit = {"schema_version": "argus.d1-collection-audit/v1", "run_id": args.run_id, "fixture_id": FIXTURE_ID,
             "request_count": 1, "concurrency": 1, "minimum_interval_seconds": 1, "raw_access": "restricted",
             "sources": [{"source": record["source"], "evidence_path": "raw/" + record["evidence_path"], "sha256": record["content_sha256"]} for record in records]}
    (run_directory / "review-redacted.json").write_text(json.dumps(review, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    (run_directory / "collection-audit.json").write_text(json.dumps(audit, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    (run_directory / "d1-runtime-manifest.json").write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    print("D1 runtime evidence collected: " + str(run_directory))


def main(args):
    """Retain only non-secret failure diagnostics; never create a partial manifest."""
    run_directory = Path(args.output_root).resolve() / args.run_id
    try:
        return collect(args)
    except Exception as exc:
        if run_directory.is_dir() and not (run_directory / "d1-runtime-manifest.json").exists():
            failure = {"schema_version": "argus.d1-collection-failure/v1", "run_id": args.run_id,
                       "fixture_id": getattr(args, "fixture_id", FIXTURE_ID), "failure_time_utc": utc_text(utc_now()),
                       "error": str(exc), "manifest_written": False}
            (run_directory / "collection-failure.json").write_text(json.dumps(failure, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        raise


def arguments():
    parser = argparse.ArgumentParser(description="Collect one real BEN-D1-OBS-001 runtime observation; no AWS writes.")
    parser.add_argument("--terraform-output-json", required=True); parser.add_argument("--output-root", required=True)
    parser.add_argument("--region", required=True); parser.add_argument("--account-id", required=True); parser.add_argument("--aws-profile")
    parser.add_argument("--hostname", required=True); parser.add_argument("--path", default="/d1/observe"); parser.add_argument("--client-cidr", required=True)
    parser.add_argument("--run-id", required=True); parser.add_argument("--request-id", required=True); parser.add_argument("--trace-id", required=True)
    parser.add_argument("--ssm-parameter-name", required=True); parser.add_argument("--canary-bucket", required=True); parser.add_argument("--canary-object-key", required=True); parser.add_argument("--canary-object-version-id", required=True)
    parser.add_argument("--host-id", required=True); parser.add_argument("--host-process", required=True); parser.add_argument("--flow-eni-id", required=True); parser.add_argument("--flow-srcaddr", required=True); parser.add_argument("--flow-dstaddr", required=True); parser.add_argument("--flow-dstport", required=True, type=int)
    parser.add_argument("--redaction-key-file", required=True); parser.add_argument("--fixture-id", default=FIXTURE_ID)
    parser.add_argument("--concurrency", type=int, default=1); parser.add_argument("--minimum-interval-seconds", type=int, default=1)
    parser.add_argument("--request-timeout-seconds", type=int, default=20); parser.add_argument("--poll-interval-seconds", type=int, default=5); parser.add_argument("--poll-timeout-seconds", type=int, default=300); parser.add_argument("--cli-timeout-seconds", type=int, default=30)
    return parser.parse_args()


if __name__ == "__main__":
    try:
        main(arguments())
    except (CollectorError, subprocess.TimeoutExpired) as exc:
        raise SystemExit("D1 runtime collection rejected: " + str(exc)) from exc
