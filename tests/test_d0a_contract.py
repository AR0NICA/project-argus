import importlib.util
import json
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

web = load("d0a_web", ROOT / "services/web/app.py")
# WAS imports the optional runtime MySQL driver; contract helpers do not need it.
fake_mysql = types.SimpleNamespace(connector=types.SimpleNamespace(Error=Exception))
sys.modules.setdefault("mysql", fake_mysql)
sys.modules.setdefault("mysql.connector", fake_mysql.connector)
was = load("d0a_was", ROOT / "services/was/app.py")
evidence_validator = load("d0a_evidence_validator", ROOT / "scripts/validate_evidence.py")

class D0AContractTests(unittest.TestCase):
    run_id = "ARGUS-20260811-LOCAL-R01"
    def test_frozen_run_id_rejects_generic_client_values(self):
        self.assertTrue(web.valid_run_id(self.run_id))
        for invalid in ("run-1", "ARGUS-2026-LOCAL-R01", "ARGUS-20260811-LOCAL-R1", "ARGUS-20260811-LOCAL-R01-x"):
            self.assertFalse(web.valid_run_id(invalid))
            self.assertFalse(was.valid_run_id(invalid))
    def test_session_is_deterministic_and_run_bound(self):
        self.assertEqual(web.session_token(self.run_id), was.session_token(self.run_id))
        self.assertNotEqual(web.session_token(self.run_id), web.session_token("ARGUS-20260812-LOCAL-R01"))
    def test_hybrid_envelope_is_explicitly_disabled(self):
        envelope = web.envelope(self.run_id, "request-0001", "/auth", b'{}')
        self.assertEqual(envelope["source"], "original_request")
        self.assertEqual(envelope["evaluation_status"], "disabled_not_evaluated")
    def test_approved_manifest_is_exact(self):
        with tempfile.TemporaryDirectory() as temp:
            original = was.EVIDENCE_ROOT; was.EVIDENCE_ROOT = Path(temp)
            try:
                d = was.EVIDENCE_ROOT / self.run_id; d.mkdir()
                d.joinpath("run-manifest.json").write_text(json.dumps({"manifest_version":"argus.d0a-local-run/v1", "run_id":self.run_id, "scenario":"D0A-LOCAL", "approval_state":"approved", "concurrency":1, "minimum_interval_seconds":1}))
                self.assertTrue(was.manifest_approved(self.run_id))
                d.joinpath("run-manifest.json").write_text("{}")
                self.assertFalse(was.manifest_approved(self.run_id))
            finally: was.EVIDENCE_ROOT = original
    def test_one_time_ticket_is_consumed_before_forwarding(self):
        ticket = "unit-ticket"; token = web.session_token(self.run_id)
        web.TICKETS[ticket] = {"run_id":self.run_id, "decision":"a", "session_hash":web.sha(token.encode()), "expires":time.time()+5, "used":False}
        self.assertIsNotNone(web.claim_ticket(self.run_id, ticket, token))
        self.assertIsNone(web.claim_ticket(self.run_id, ticket, token))
    def test_expired_ticket_and_no_session_are_rejected(self):
        ticket = "expired-ticket"; token = web.session_token(self.run_id)
        web.TICKETS[ticket] = {"run_id":self.run_id, "decision":"a", "session_hash":web.sha(token.encode()), "expires":time.time()-1, "used":False}
        self.assertIsNone(web.claim_ticket(self.run_id, ticket, token))
        self.assertIsNone(web.claim_ticket(self.run_id, ticket, ""))
    def test_event_id_and_size_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            original = was.EVIDENCE_ROOT; was.EVIDENCE_ROOT = Path(temp)
            try:
                (was.EVIDENCE_ROOT / self.run_id).mkdir()
                event = was.append_event(self.run_id, "S02", 1, "unit", "request-0001", "accepted", fixture_id="ATK-S02-SYNTH-AUTH-01", content_sha256="0" * 64)
                self.assertEqual(event["evidence_id"], self.run_id + "-S02-E01")
                with self.assertRaises(ValueError):
                    was.append_event(self.run_id, "S02", 1, "unit", "request-0001", "accepted", fixture_id="x", content_sha256="0" * 64, oversized="x" * 40000)
            finally: was.EVIDENCE_ROOT = original
    def make_valid_evidence(self, temp):
        evidence_root = Path(temp) / "evidence"; directory = evidence_root / self.run_id; directory.mkdir(parents=True)
        directory.joinpath("run-manifest.json").write_text(json.dumps({"manifest_version":"argus.d0a-local-run/v1","run_id":self.run_id,"scenario":"D0A-LOCAL","approval_state":"approved","concurrency":1,"minimum_interval_seconds":1}))
        provenance = {"run_id":self.run_id, "fixture_sha256":evidence_validator.sha_file(ROOT / "fixtures/d0a-local-fixtures.json"), "seed_sha256":evidence_validator.sha_file(ROOT / "mysql/init.sql"), "event_schema_sha256":evidence_validator.sha_file(ROOT / "schemas/event-v1.json"), "hybridnb_schema_sha256":evidence_validator.sha_file(ROOT / "schemas/hybridnb-request-envelope-v1.json"), "compose_images":"[]"}
        directory.joinpath("provenance.json").write_text(json.dumps(provenance))
        auth, mark = self.run_id + "-AUTH", self.run_id + "-MARK"; body, decision, session = "a" * 64, "b" * 64, "c" * 64
        ticket, context = "123e4567-e89b-42d3-a456-426614174000", "123e4567-e89b-42d3-a456-426614174001"
        envelope = {"schema_version":"argus.hybridnb-envelope/v1","request_id":auth,"run_id":self.run_id,"source":"original_request","method":"POST","path":"/auth","body_sha256":body,"evaluation_status":"disabled_not_evaluated"}
        def event(stage, seq, kind, result, fixture, request, source, target, content, corr, extra=None):
            item = {"schema_version":"argus.event/v1","evidence_id":f"{self.run_id}-{stage}-E{seq:02d}","event_time_utc":f"2026-08-11T00:00:0{seq}Z","run_id":self.run_id,"stage_id":stage,"event_type":kind,"request_id":request,"result":result,"source_ref":source,"target_ref":target,"action":kind,"fixture_or_resource_id":fixture,"fixture_id":fixture,"content_sha256":content,"collector":"d0a-local-runner","reviewer":None,"redaction_status":"synthetic_no_redaction_required","secret_material_present":False,"correlation":corr}
            if extra: item.update(extra)
            return item
        marker = {"marker_schema_version":"argus.fixed-marker/v1","run_id":self.run_id,"request_id":mark,"fixture_id":"ATK-S04-MARKER-01","operation":"write_fixed_marker","timestamp_utc":"2026-08-11T00:00:04Z","non_destructive":True,"auth_decision_hash":decision,"admin_session_hash":session,"upload_ticket_id":ticket,"web_action_context_id":context}
        marker_raw = json.dumps(marker, separators=(",",":"), sort_keys=True).encode(); marker_sha = __import__("hashlib").sha256(marker_raw).hexdigest(); directory.joinpath("marker.json").write_bytes(marker_raw)
        events = [event("S02",1,"fixed_sqli_auth_fixture","accepted","ATK-S02-SYNTH-AUTH-01",auth,"was","synthetic_mysql_auth",body,{"principal":"synthetic_admin","auth_decision_hash":decision},{"original_request_envelope":envelope}), event("S02",2,"hybridnb_adapter","not_evaluated","ATK-S02-SYNTH-AUTH-01",auth,"was","synthetic_mysql_auth",body,{"adapter":"disabled_not_evaluated","crs_fields_consumed":False},{"original_request_envelope":envelope}), event("S03",3,"administrator_session_issued","authorized","ATK-S02-SYNTH-AUTH-01",auth,"web","was_fixed_actions",session,{"auth_decision_hash":decision,"admin_session_hash":session,"upload_ticket_id":ticket,"ttl_seconds":120,"one_time":True}), event("S04",4,"fixed_marker_written","written","ATK-S04-MARKER-01",mark,"was","task_local_evidence_volume",marker_sha,{"web_marker_sha256":marker_sha,"web_action_context_id":context,"auth_decision_hash":decision,"admin_session_hash":session,"upload_ticket_id":ticket,"non_destructive":True},{"response_sha256":marker_sha})]
        directory.joinpath("events.jsonl").write_text("\n".join(json.dumps(item,separators=(",",":"),sort_keys=True) for item in events) + "\n")
        taps = [{"schema_version":"argus.waf-tap/v1","run_id":self.run_id,"request_id":auth,"method":"POST","uri":"/auth","status":200,"crs_engine":"detection_only"},{"schema_version":"argus.waf-tap/v1","run_id":self.run_id,"request_id":mark,"method":"POST","uri":"/admin/marker","status":200,"crs_engine":"detection_only"}]
        (evidence_root / "waf-request-tap.jsonl").write_text("\n".join(json.dumps(item) for item in taps) + "\n")
        return evidence_root, directory
    def test_evidence_validator_rejects_duplicate_wrong_stage_and_wrong_tap(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory = self.make_valid_evidence(temp)
            self.assertIn("passed", evidence_validator.validate(root, self.run_id, ROOT))
            events = directory / "events.jsonl"; lines = events.read_text().splitlines(); events.write_text("\n".join(lines + [lines[-1]]) + "\n")
            with self.assertRaises(ValueError): evidence_validator.validate(root, self.run_id, ROOT)
            events.write_text("\n".join(lines) + "\n"); wrong = json.loads(lines[2]); wrong["stage_id"] = "S02"; lines[2] = json.dumps(wrong); events.write_text("\n".join(lines) + "\n")
            with self.assertRaises(ValueError): evidence_validator.validate(root, self.run_id, ROOT)
        with tempfile.TemporaryDirectory() as temp:
            root, _ = self.make_valid_evidence(temp); tap = root / "waf-request-tap.jsonl"; rows = [json.loads(x) for x in tap.read_text().splitlines()]; rows[1]["status"] = 201; tap.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
            with self.assertRaises(ValueError): evidence_validator.validate(root, self.run_id, ROOT)
        with tempfile.TemporaryDirectory() as temp:
            root, directory = self.make_valid_evidence(temp); events = directory / "events.jsonl"; rows = [json.loads(x) for x in events.read_text().splitlines()]; rows[2]["correlation"]["ttl_seconds"] = 119; events.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
            with self.assertRaises(ValueError): evidence_validator.validate(root, self.run_id, ROOT)

if __name__ == "__main__": unittest.main()
