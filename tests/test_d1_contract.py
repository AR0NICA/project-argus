import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("d1_validator", ROOT / "observability/validate_d1_manifest.py")
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def source_anchors(manifest):
    run_id = manifest["run_id"]
    request_id = manifest["application_request_id"]
    return {
        "alb": {"trace_id": "Root=1-66b00000-abcdef0123456789", "request_anchor": "GET /health 200", "path": "/health"},
        "nginx_modsecurity": {"run_id": run_id, "request_id": request_id, "transaction_id": "nginx-tx-0001"},
        "d0_envelope": {"run_id": run_id, "request_id": request_id, "body_sha256": "a" * 64},
        "web": {"run_id": run_id, "request_id": request_id, "session_hash": "b" * 64},
        "was": {"run_id": run_id, "request_id": request_id, "service_request_id": "was-request-0001"},
        "host": {"host_id": "i-0123456789abcdef0", "process": "argus-web", "pid": 1234, "audit_epoch": 1786406406, "audit_serial": 1201},
        "flow_logs": {"eni_id": "eni-0123456789abcdef0", "srcaddr": "10.20.0.10", "dstaddr": "10.20.10.10", "srcport": 443, "dstport": 8080, "protocol": 6, "start_epoch": 1786406407, "end_epoch": 1786406408},
        "cloudtrail": {"event_id": "cloudtrail-event-0001", "aws_request_id": "aws-request-0001", "event_name": "DescribeInstances", "resource": "arn:aws:ec2:ap-northeast-2:111111111111:instance/i-0123456789abcdef0", "principal": "arn:aws:iam::111111111111:role/argus-d1"},
        "s3_getobject": {"event_id": "s3-event-0001", "aws_request_id": "s3-request-0001", "event_name": "GetObject", "bucket": "argus-d1-canary", "key": "scoped/benign-object.txt", "version_id": "3HL4kqtJlcpXroDTDmjVBH40Nrjfkd", "principal": "arn:aws:iam::111111111111:role/argus-d1"},
        "rds": {"db_instance": "argus-base-db", "connection_id": 42, "query_id": "query-0001"},
    }


def raw_export(source, event_time, anchors):
    """Small source-shaped benign export with the native time and anchors."""
    if source == "flow_logs":
        return ("2 111111111111 {eni_id} {srcaddr} {dstaddr} {srcport} {dstport} {protocol} "
                "1 84 {start_epoch} {end_epoch} ACCEPT OK\n").format(**anchors).encode("utf-8")
    if source == "host":
        return ("node={host_id} type=SYSCALL msg=audit({audit_epoch}.000:{audit_serial}): "
                "arch=c000003e syscall=59 success=yes pid={pid} comm=\"{process}\"\n").format(**anchors).encode("utf-8")
    document = {"timestamp": event_time, "source": source, "anchors": anchors}
    if source == "nginx_modsecurity": document["service"] = "nginx modsecurity"
    elif source == "d0_envelope": document.update({"schema": "argus.hybridnb-envelope/v1", "adapter_status": "disabled_not_evaluated"})
    elif source == "web": document["service"] = "web"
    elif source == "was": document["service"] = "was"
    elif source == "cloudtrail": document["eventID"] = anchors["event_id"]
    elif source == "s3_getobject": document.update({"eventName": "GetObject", "resources_type": "AWS::S3::Object"})
    elif source == "rds": document["log_type"] = "general"
    return json.dumps(document, sort_keys=True).encode("utf-8")


def runtime_manifest(root):
    manifest = json.loads((ROOT / "fixtures/d1-benign-manifest.json").read_text(encoding="utf-8"))
    manifest["proof_kind"] = "runtime"
    anchors_by_source = source_anchors(manifest)
    records = []
    for index, source in enumerate(validator.REQUIRED_SOURCES, start=1):
        event_time = f"2026-08-11T00:00:{index:02d}Z"
        raw = raw_export(source, event_time, anchors_by_source[source])
        relative_path = source + ".json"
        (root / relative_path).write_bytes(raw)
        record = {
            "source": source,
            "event_time_utc": event_time,
            "evidence_path": relative_path,
            "content_sha256": hashlib.sha256(raw).hexdigest(),
            "collector": "d1-local-gate",
            "redaction_status": "disabled_not_evaluated" if source == "d0_envelope" else "synthetic",
            "evidence_kind": validator.EVIDENCE_KINDS[source],
            "anchors": anchors_by_source[source],
        }
        if source == "s3_getobject":
            record["scope"] = "scoped_getobject"
        records.append(record)
    manifest["records"] = records
    return manifest


class D1ContractTests(unittest.TestCase):
    def test_benign_plan_is_structural_not_runtime_proof(self):
        manifest = json.loads((ROOT / "fixtures/d1-benign-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(validator.validate(manifest), {"proof_kind": "plan", "runtime_proven": False})

    def test_attack_fixture_is_refused(self):
        manifest = json.loads((ROOT / "fixtures/d1-benign-manifest.json").read_text(encoding="utf-8"))
        manifest["fixture_id"] = "ATK-S02-001"
        with self.assertRaises(ValueError):
            validator.validate(manifest)

    def test_runtime_requires_distinct_hashed_source_native_raw_exports(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            evidence_root = Path(temporary_directory)
            manifest = runtime_manifest(evidence_root)
            self.assertTrue(validator.validate(manifest, evidence_root)["runtime_proven"])
            self.assertNotIn(manifest["run_id"].encode("utf-8"), (evidence_root / "alb.json").read_bytes())
            with self.assertRaises(ValueError):
                validator.validate(manifest)
            broken_hash = copy.deepcopy(manifest)
            broken_hash["records"][0]["content_sha256"] = "b" * 64
            with self.assertRaises(ValueError):
                validator.validate(broken_hash, evidence_root)
            duplicate_path = copy.deepcopy(manifest)
            duplicate_path["records"][1]["evidence_path"] = duplicate_path["records"][0]["evidence_path"]
            with self.assertRaises(ValueError):
                validator.validate(duplicate_path, evidence_root)

    def test_native_anchor_semantics_reject_tuple_event_and_window_mutations(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            evidence_root = Path(temporary_directory)
            manifest = runtime_manifest(evidence_root)
            flow_mismatch = copy.deepcopy(manifest)
            flow_mismatch["records"][6]["anchors"]["dstport"] = 9090
            with self.assertRaises(ValueError):
                validator.validate(flow_mismatch, evidence_root)
            s3_mismatch = copy.deepcopy(manifest)
            s3_mismatch["records"][8]["anchors"]["event_name"] = "PutObject"
            with self.assertRaises(ValueError):
                validator.validate(s3_mismatch, evidence_root)
            outside_window = copy.deepcopy(manifest)
            outside_window["records"][9]["event_time_utc"] = "2026-08-11T00:10:01Z"
            with self.assertRaises(ValueError):
                validator.validate(outside_window, evidence_root)

    def test_application_and_schema_bounds_reject_universal_or_stale_contracts(self):
        manifest = json.loads((ROOT / "fixtures/d1-benign-manifest.json").read_text(encoding="utf-8"))
        manifest["application_request_id"] = "r" * 129
        with self.assertRaises(ValueError):
            validator.validate(manifest)
        with tempfile.TemporaryDirectory() as temporary_directory:
            evidence_root = Path(temporary_directory)
            runtime = runtime_manifest(evidence_root)
            impossible_alb = copy.deepcopy(runtime)
            impossible_alb["records"][0]["anchors"]["run_id"] = runtime["run_id"]
            with self.assertRaises(ValueError):
                validator.validate(impossible_alb, evidence_root)
            stale_audit = copy.deepcopy(runtime)
            stale_audit["records"][-1]["evidence_kind"] = "rds_audit_log"
            with self.assertRaises(ValueError):
                validator.validate(stale_audit, evidence_root)
