import hashlib
import importlib.util
import json
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


web = load("d1_runtime_web", ROOT / "services/web/app.py")
fake_mysql = types.SimpleNamespace(connector=types.SimpleNamespace(Error=Exception))
sys.modules.setdefault("mysql", fake_mysql)
sys.modules.setdefault("mysql.connector", fake_mysql.connector)
was = load("d1_runtime_was", ROOT / "services/was/app.py")


class Body:
    def __init__(self, value): self.value, self.closed = value, False
    def read(self, size): return self.value
    def close(self): self.closed = True


class D1RuntimeAppTests(unittest.TestCase):
    run_id = "ARGUS-20260813-BASE-R01"
    request_id = "d1-runtime-request-0001"

    def setUp(self):
        web.D1_LAST_OBSERVE = 0.0
        was.D1_LAST_OBSERVE = 0.0

    def test_base_run_ids_do_not_expand_the_d0a_local_contract(self):
        self.assertTrue(web.valid_base_run_id(self.run_id))
        self.assertTrue(was.valid_base_run_id(self.run_id))
        self.assertFalse(web.valid_run_id(self.run_id))
        self.assertFalse(was.valid_run_id("ARGUS-20260813-BASE-R1"))

    def test_web_uses_exact_versioned_getobject_and_non_decrypted_sentinel(self):
        calls, body = [], Body(b"approved benign object")
        class Client:
            def __init__(self, service): self.service = service
            def get_object(self, **kwargs): calls.append((self.service, kwargs)); return {"Body": body}
            def get_parameter(self, **kwargs): calls.append((self.service, kwargs)); return {"Parameter": {"Value": "not-returned"}}
        class Session:
            def __init__(self, **kwargs): calls.append(("session", kwargs))
            def client(self, service): return Client(service)
        result = web.d1_aws_observe({"bucket":"approved-bucket", "key":"scoped/object.txt", "version_id":"v-123", "parameter_name":"/argus/base/d1/sentinel", "region":"ap-northeast-2"}, Session)
        self.assertEqual(calls[1], ("s3", {"Bucket":"approved-bucket", "Key":"scoped/object.txt", "VersionId":"v-123"}))
        self.assertEqual(calls[2], ("ssm", {"Name":"/argus/base/d1/sentinel", "WithDecryption":False}))
        self.assertTrue(body.closed)
        self.assertEqual(result["s3_content_sha256"], hashlib.sha256(b"approved benign object").hexdigest())
        self.assertNotIn("not-returned", json.dumps(result))

    def test_repository_canary_is_fixed_benign_and_bounded(self):
        raw = (ROOT / "fixtures/d1-canary.json").read_bytes()
        document = json.loads(raw)
        self.assertLessEqual(len(raw), web.MAX_BYTES)
        self.assertEqual(document, {
            "fixture_id": "BEN-D1-OBS-001",
            "kind": "synthetic_canary",
            "schema_version": "argus.d1-canary/v1",
            "summary": "Fixed benign object for exact-version D1 S3 observation.",
        })

    def test_was_query_is_fixed_parameterized_and_capped(self):
        calls = []
        class Cursor:
            def execute(self, statement, args): calls.append((statement, args))
            def fetchmany(self, limit): calls.append(("fetchmany", limit)); return [{"record_id": 1, "category": "synthetic", "summary": "one"}]
        class DB:
            def cursor(self, dictionary):
                if not dictionary: raise AssertionError("D1 rows must be dictionary-shaped")
                return Cursor()
            def close(self): calls.append(("close",))
        original = getattr(was.mysql.connector, "connect", None)
        was.mysql.connector.connect = lambda **kwargs: DB()
        try:
            query_id = "123e4567-e89b-42d3-a456-426614174000"
            rows = was.d1_synthetic_select(self.request_id, query_id)
        finally:
            if original is None:
                del was.mysql.connector.connect
            else:
                was.mysql.connector.connect = original
        self.assertEqual(len(rows), 1)
        self.assertIn("LIMIT 10", calls[0][0])
        self.assertIn("argus_d1_query_id=" + query_id, calls[0][0])
        self.assertIn("argus_request_id=" + self.request_id, calls[0][0])
        self.assertEqual(calls[0][1], ("BEN-D1-OBS-001",))
        self.assertEqual(calls[1], ("fetchmany", 11))

    def test_marker_path_is_fixed_by_code_and_contains_no_secret(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            original = was.D1_AUDIT_MARKER_PATH
            was.D1_AUDIT_MARKER_PATH = Path(temporary_directory) / "fixed" / "argus-d1-observe.marker"
            try:
                marker_sha = was.write_d1_audit_marker(self.run_id, self.request_id, "123e4567-e89b-42d3-a456-426614174000")
                raw = was.D1_AUDIT_MARKER_PATH.read_bytes()
            finally:
                was.D1_AUDIT_MARKER_PATH = original
        self.assertEqual(marker_sha, hashlib.sha256(raw).hexdigest())
        self.assertNotIn(b"password", raw.lower())
        self.assertIn(b"BEN-D1-OBS-001", raw)

    def test_was_source_log_has_collector_service_request_anchor_and_file_secret_input(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            secret = root / "db-password"
            secret.write_text("dedicated-reader-password\n", encoding="utf-8")
            original_root, original_file = was.D1_LOG_ROOT, __import__("os").environ.get("DB_PASSWORD_FILE")
            was.D1_LOG_ROOT = root / "logs"
            __import__("os").environ["DB_PASSWORD_FILE"] = str(secret)
            try:
                self.assertEqual(was.d1_db_password(), "dedicated-reader-password")
                item = was.d1_source_log("d1_synthetic_select", run_id=self.run_id, request_id=self.request_id,
                    service_request_id="was-d1-query-0001", query_id="query-0001", row_count=1)
                raw = (was.D1_LOG_ROOT / "was.jsonl").read_text(encoding="utf-8")
            finally:
                was.D1_LOG_ROOT = original_root
                if original_file is None:
                    del __import__("os").environ["DB_PASSWORD_FILE"]
                else:
                    __import__("os").environ["DB_PASSWORD_FILE"] = original_file
        self.assertEqual(item["service_request_id"], "was-d1-query-0001")
        self.assertNotIn("dedicated-reader-password", raw)

    def test_web_endpoint_relays_only_benign_d1_with_disabled_detectors(self):
        original_config, original_aws, original_was = web.d1_runtime_config, web.d1_aws_observe, web.was_get
        original_log_root = web.D1_LOG_ROOT
        captured = []
        web.d1_runtime_config = lambda: {"unused": "config"}
        web.d1_aws_observe = lambda config: {"s3_version_id":"version", "s3_content_sha256":"a" * 64, "ssm_parameter_name_sha256":"b" * 64}
        def fake_was_get(path, headers):
            captured.append((path, headers))
            return {"fixture_id":"BEN-D1-OBS-001", "query_id":"123e4567-e89b-42d3-a456-426614174000", "row_count":1, "row_set_sha256":"c" * 64, "audit_marker_sha256":"d" * 64}
        web.was_get = fake_was_get
        with tempfile.TemporaryDirectory() as temporary_directory:
            web.D1_LOG_ROOT = Path(temporary_directory)
            server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = "http://127.0.0.1:%d/d1/observe" % server.server_port
                headers = {"X-ARGUS-Run-Id":self.run_id, "X-ARGUS-Request-Id":self.request_id, "X-ARGUS-Fixture-Id":"BEN-D1-OBS-001"}
                request = urllib.request.Request(url, headers=headers, method="GET")
                with urllib.request.urlopen(request, timeout=3) as response:
                    document = json.loads(response.read())
                self.assertEqual(document["row_count"], 1)
                self.assertEqual(document["waf_status"], "disabled_not_evaluated")
                self.assertEqual(document["hybridnb_status"], "disabled_not_evaluated")
                self.assertEqual(captured[0][0], "/d1/observe")
                self.assertEqual(captured[0][1]["X-ARGUS-Internal-Caller"], "web-d1")
                bad = urllib.request.Request(url, headers={**headers, "X-ARGUS-Fixture-Id":"ATK-D1-001"}, method="GET")
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    urllib.request.urlopen(bad, timeout=3)
                self.assertEqual(raised.exception.code, 403)
                envelope = json.loads((web.D1_LOG_ROOT / "d0_envelope.jsonl").read_text(encoding="utf-8"))
                web_event = json.loads((web.D1_LOG_ROOT / "web.jsonl").read_text(encoding="utf-8"))
                self.assertEqual(envelope["body_sha256"], hashlib.sha256(b"").hexdigest())
                self.assertEqual(envelope["evaluation_status"], "disabled_not_evaluated")
                self.assertEqual(web_event["session_hash"], web.d1_session_hash(self.run_id, self.request_id))
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=3)
                web.d1_runtime_config, web.d1_aws_observe, web.was_get, web.D1_LOG_ROOT = original_config, original_aws, original_was, original_log_root

    def test_base_headers_do_not_grant_access_to_attack_paths_or_expose_sdk_errors(self):
        original_config, original_aws = web.d1_runtime_config, web.d1_aws_observe
        original_log_root = web.D1_LOG_ROOT
        web.d1_runtime_config = lambda: {"unused": "config"}
        web.d1_aws_observe = lambda config: (_ for _ in ()).throw(RuntimeError("secret-value and approved-bucket must not leak"))
        with tempfile.TemporaryDirectory() as temporary_directory:
            web.D1_LOG_ROOT = Path(temporary_directory)
            server = ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_headers = {"X-ARGUS-Run-Id":self.run_id, "X-ARGUS-Request-Id":self.request_id, "X-ARGUS-Fixture-Id":"BEN-D1-OBS-001"}
                request = urllib.request.Request("http://127.0.0.1:%d/d1/observe" % server.server_port, headers=base_headers, method="GET")
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(request, timeout=3)
                response = rejected.exception.read().decode("utf-8")
                self.assertEqual(rejected.exception.code, 503)
                self.assertNotIn("secret-value", response)
                self.assertNotIn("approved-bucket", response)
                attack = urllib.request.Request("http://127.0.0.1:%d/auth" % server.server_port, data=json.dumps({"run_id":self.run_id, "fixture_id":"ATK-S02-SYNTH-AUTH-01", "probe":"fixture-token-v1"}).encode("utf-8"), headers={"X-ARGUS-Run-Id":self.run_id, "X-ARGUS-Request-Id":self.request_id, "Content-Type":"application/json"}, method="POST")
                with self.assertRaises(urllib.error.HTTPError) as attack_rejected:
                    urllib.request.urlopen(attack, timeout=3)
                self.assertEqual(attack_rejected.exception.code, 400)
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=3)
                web.d1_runtime_config, web.d1_aws_observe, web.D1_LOG_ROOT = original_config, original_aws, original_log_root

    def test_gateway_preserves_fixture_header_and_forces_benign_audit_records(self):
        nginx = (ROOT / "services/gateway/nginx.conf").read_text(encoding="utf-8")
        modsecurity = (ROOT / "services/gateway/modsecurity.conf").read_text(encoding="utf-8")
        self.assertIn("proxy_set_header X-ARGUS-Fixture-Id $http_x_argus_fixture_id", nginx)
        self.assertIn('"service":"nginx modsecurity"', nginx)
        self.assertIn('"transaction_id":"$request_id"', nginx)
        self.assertIn("SecAuditEngine On", modsecurity)

    def test_production_images_do_not_use_flask_and_require_hash_locked_dependencies(self):
        web_docker = (ROOT / "services/web/Dockerfile").read_text(encoding="utf-8")
        was_docker = (ROOT / "services/was/Dockerfile").read_text(encoding="utf-8")
        self.assertNotIn("flask", web_docker.lower())
        self.assertNotIn("flask", was_docker.lower())
        self.assertIn("--require-hashes", web_docker)
        self.assertIn("--require-hashes", was_docker)


if __name__ == "__main__":
    unittest.main()
