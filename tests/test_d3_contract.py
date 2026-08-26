import hashlib
import json
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "scripts"))

# Import by name (not importlib file-loading) so every module shares one d3_core
# instance; otherwise the validator's D3Error class would differ from this test's.
import d3_core as core  # noqa: E402
import validate_d3_evidence as validator  # noqa: E402
import run_d3_unit as runner  # noqa: E402
import collect_d3_runtime as collect  # noqa: E402
import run_d3_gate as gate  # noqa: E402

WINDOW = {"start_utc": "2026-08-24T00:00:00Z", "end_utc": "2026-08-24T01:00:00Z"}


def make_source(directory, stage, run_id, event_time_utc, source=None, corrupt=False):
    src = source if source is not None else sorted(validator.RUNTIME_SOURCES[stage])[0]
    if src in {"cloudtrail", "s3_data_event"}:
        native = "11111111-1111-4111-8111-" + ("0" * 11) + stage[-1]
        event_name = "GetCallerIdentity" if stage == "S06" else "GetObject"
        event_source = "sts.amazonaws.com" if stage == "S06" else "s3.amazonaws.com"
        item = {"eventID": native, "eventTime": event_time_utc, "eventSource": event_source, "eventName": event_name}
        if stage == "S07":
            item["requestParameters"] = {"key": "canary.txt", "versionId": "version-01"}
        text = json.dumps({"Records": [item]}, separators=(",", ":"))
    elif src == "flow_logs":
        native = "eni-0abc" + stage.lower()
        epoch = int(core.parse_utc(event_time_utc).timestamp())
        text = "2 123456789012 %s 10.0.1.10 10.0.2.20 51000 443 6 1 128 %d %d ACCEPT OK" % (native, epoch - 1, epoch + 1)
    elif src == "alb_access":
        native = "Root=1-abcdef01-" + ("0" * 23) + stage[-1]
        text = 'https %s app/argus/123 10.0.0.1:443 10.0.1.1:8080 0 0 0 200 200 1 1 "GET / HTTP/1.1" "test" - - arn "-" "-" 0 %s' % (event_time_utc, native)
    elif src == "auditd":
        epoch = core.parse_utc(event_time_utc).timestamp()
        native = "audit(%.3f:%d)" % (epoch, int(stage[-2:]))
        text = "type=SYSCALL msg=%s arch=c000003e syscall=1 success=yes" % native
    elif src == "nginx_modsecurity":
        native = "NGINX-REQ-" + stage
        text = json.dumps({"source": "nginx", "event_time_utc": event_time_utc, "request_id": native}, separators=(",", ":"))
    elif src == "rds_audit":
        native = "RDS-THREAD-" + stage
        text = "%s,%s,QUERY,ARGUS-Q01,SELECT synthetic_value" % (event_time_utc, native)
    else:
        native = "NID-" + stage
        text = native
    anchors = [native]
    rel = "raw/%s-%s.log" % (stage, src)
    raw_path = directory / rel
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(text, encoding="utf-8")
    sha = hashlib.sha256(raw_path.read_bytes()).hexdigest()
    if corrupt:
        raw_path.write_text(text + " tampered", encoding="utf-8")
    return {"source": src, "event_time_utc": event_time_utc, "evidence_path": rel, "content_sha256": sha, "collector": "op", "redaction_status": "independent", "native_record_id": native, "anchors": anchors}


def runtime_input(bundle, directory, run_id, source_override=None, corrupt=False):
    observations = {}
    stages = []
    for event in bundle["events"]:
        if not event["evidence_id"].endswith("-E01"):
            continue
        stage = event["stage_id"]
        stages.append(stage)
        record = make_source(directory, stage, run_id, event["event_time_utc"], source=source_override, corrupt=corrupt)
        obs = {"event_time_utc": event["event_time_utc"], "success_token_kind": event["success_token_kind"], "success_token_value": event["success_token_value"], "content_sha256": event["content_sha256"], "handoff_in_id": event["handoff_in_id"], "handoff_out_id": event["handoff_out_id"], "harness_injected": event["harness_injected"], "runtime_sources": [record]}
        if stage in ("S09", "S10"):
            obs["result_guard"] = event["result_guard"]
        observations[stage] = obs
    return {"input_version": collect.INPUT_VERSION, "run_id": run_id, "run_window": WINDOW, "stages": stages, "observations": observations, "handoffs": bundle["handoffs"]}

RUN = "ARGUS-20260824-BASE-R01"
START = core.parse_utc("2026-08-24T00:00:00Z")


def materialize(temp, run_id, stages, harness):
    bundle = core.run_unit(run_id, stages, harness_allowed=harness, start_utc=START)
    root = Path(temp) / "evidence"
    directory = root / run_id
    directory.mkdir(parents=True)
    directory.joinpath("run-manifest.json").write_text(json.dumps(bundle["manifest"], separators=(",", ":"), sort_keys=True))
    directory.joinpath("provenance.json").write_text(json.dumps(runner.build_provenance(run_id), separators=(",", ":"), sort_keys=True))
    runner.write_jsonl(directory / "events.jsonl", bundle["events"])
    runner.write_jsonl(directory / "handoffs.jsonl", bundle["handoffs"])
    return root, directory, bundle


def rewrite_jsonl(path, rows):
    path.write_text("".join(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in rows))


class D3EngineTests(unittest.TestCase):
    def test_success_token_is_run_and_chain_bound(self):
        a = core.success_token(RUN, "S02", "auth_decision_hash", "ATK-S02-SYNTH-AUTH-01", "pred", "hash")
        run_bound = core.success_token("ARGUS-20260824-BASE-R02", "S02", "auth_decision_hash", "ATK-S02-SYNTH-AUTH-01", "pred", "hash")
        chain_bound = core.success_token(RUN, "S02", "auth_decision_hash", "ATK-S02-SYNTH-AUTH-01", "other", "hash")
        self.assertNotEqual(a, run_bound)
        self.assertNotEqual(a, chain_bound)
        self.assertTrue(core.SHA_RE.fullmatch(a))
        self.assertTrue(core.EVENT_ID_RE.fullmatch(core.success_token(RUN, "S06", "external_identity_event_id", "ATK-S06-STS-01", "p", "event_id")))
        self.assertTrue(core.MANIFEST_ID_RE.fullmatch(core.success_token(RUN, "S09", "db_result_manifest_id", "ATK-S09-ARGUS-Q01", "p", "manifest_id")))

    def test_handoff_forged_reused_expired_crossrun_wrongkind_wrongstage(self):
        led = core.HandoffLedger()
        hid = led.issue("upload_ticket_id", RUN, "S03", "a" * 64, "hash", START)
        with self.assertRaises(core.HandoffError):  # forged
            led.consume("00000000-0000-4000-8000-000000000000", RUN, "upload_ticket_id", "S04", START)
        with self.assertRaises(core.HandoffError):  # cross-run
            led.consume(hid, "ARGUS-20260824-BASE-R09", "upload_ticket_id", "S04", START)
        with self.assertRaises(core.HandoffError):  # wrong kind
            led.consume(hid, RUN, "auth_decision_id", "S04", START)
        with self.assertRaises(core.HandoffError):  # wrong consuming stage
            led.consume(hid, RUN, "upload_ticket_id", "S05", START)
        self.assertIsNotNone(led.consume(hid, RUN, "upload_ticket_id", "S04", START))
        with self.assertRaises(core.HandoffError):  # reuse (one-time)
            led.consume(hid, RUN, "upload_ticket_id", "S04", START)
        expiring = led.issue("auth_decision_id", RUN, "S02", "b" * 64, "hash", START)
        with self.assertRaises(core.HandoffError):  # expired
            led.consume(expiring, RUN, "auth_decision_id", "S03", START + timedelta(seconds=121))

    def test_guards_and_allow_list_and_secret(self):
        with self.assertRaises(core.GuardError):
            core.guard_result([{}] * 11, b"{}")
        with self.assertRaises(core.GuardError):
            core.guard_result([{}], b"x" * (core.MAX_BYTES + 1))
        with self.assertRaises(core.GuardError):
            core.guard_counts(11, 10)
        with self.assertRaises(core.GuardError):
            core.guard_counts(1, core.MAX_BYTES + 1)
        with self.assertRaises(core.GuardError):
            core.assert_action_allowed("SHELL")
        for good in core.ALLOWED_ACTIONS:
            core.assert_action_allowed(good)
        with self.assertRaises(core.SecretLeakError):
            core.assert_no_secret({"x": "AKIAABCDEFGHIJKLMNOP"})
        with self.assertRaises(core.SecretLeakError):
            core.assert_no_secret({"x": "password=hunter2"})

    def test_harness_disabled_blocks_missing_predecessor(self):
        with self.assertRaises(core.HandoffError):
            core.run_unit(RUN, ["S07"], harness_allowed=False, start_utc=START)

    def test_stage_order_enforced(self):
        with self.assertRaises(core.D3Error):
            core.run_unit(RUN, ["S03", "S02"], harness_allowed=True, start_utc=START)


class D3EvidenceTests(unittest.TestCase):
    def test_local_full_chain_validates_but_is_not_golden(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _, bundle = materialize(temp, RUN, list(core.STAGE_ORDER), harness=False)
            self.assertFalse(bundle["manifest"]["counts_toward_golden_chain"])  # synthetic never golden
            self.assertEqual(bundle["manifest"]["harness_injected_handoffs"], [])
            self.assertIn("passed", validator.validate(root, RUN, ROOT))

    def test_local_synthetic_cannot_be_golden_even_full_chain(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize(temp, RUN, list(core.STAGE_ORDER), harness=False)
            manifest = json.loads((directory / "run-manifest.json").read_text())
            self.assertEqual(manifest["proof_kind"], "local_synthetic")
            manifest["counts_toward_golden_chain"] = True  # forge golden on synthetic
            (directory / "run-manifest.json").write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_unit_stage_with_harness_is_not_golden(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _, bundle = materialize(temp, RUN, ["S09"], harness=True)
            self.assertFalse(bundle["manifest"]["counts_toward_golden_chain"])
            self.assertEqual(bundle["manifest"]["harness_injected_handoffs"], ["db_read_ticket_id"])
            self.assertIn("passed", validator.validate(root, RUN, ROOT))

    def test_every_stage_runs_as_a_unit(self):
        with tempfile.TemporaryDirectory() as temp:
            for i, stage in enumerate(core.STAGE_ORDER):
                run_id = "ARGUS-20260824-BASE-R%02d" % (i + 10)
                root, _, _ = materialize(temp, run_id, [stage], harness=(stage != "S01"))
                self.assertIn("passed", validator.validate(root, run_id, ROOT))

    def test_forged_handoff_in_id_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize(temp, RUN, ["S07"], harness=True)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            events[0]["handoff_in_id"] = "11111111-1111-4111-8111-111111111111"
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_oversize_result_guard_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize(temp, RUN, ["S09"], harness=True)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            events[0]["result_guard"]["row_count"] = 11
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_reused_handoff_flag_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize(temp, RUN, list(core.STAGE_ORDER), harness=False)
            handoffs = [json.loads(x) for x in (directory / "handoffs.jsonl").read_text().splitlines()]
            # Mark the first consumed handoff as never consumed while its event still points at it.
            for record in handoffs:
                if record["consumed"]:
                    record["consumed"] = False
                    record["consumed_at_utc"] = None
                    record["consumed_by_stage"] = None
                    break
            rewrite_jsonl(directory / "handoffs.jsonl", handoffs)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_timestamp_spacing_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize(temp, RUN, ["S01", "S02"], harness=True)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            first = events[0]["event_time_utc"]
            for event in events:
                if event["stage_id"] == "S02":
                    event["event_time_utc"] = first
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_tampered_golden_flag_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize(temp, RUN, ["S05"], harness=True)
            manifest = json.loads((directory / "run-manifest.json").read_text())
            manifest["counts_toward_golden_chain"] = True
            (directory / "run-manifest.json").write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_secret_leak_in_event_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize(temp, RUN, ["S06"], harness=True)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            events[0]["correlation"]["leak"] = "AKIAABCDEFGHIJKLMNOP"
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_provenance_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize(temp, RUN, ["S02"], harness=True)
            provenance = json.loads((directory / "provenance.json").read_text())
            provenance["core_sha256"] = "0" * 64
            (directory / "provenance.json").write_text(json.dumps(provenance, separators=(",", ":"), sort_keys=True))
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_local_runner_refuses_existing_run_id(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            (root / RUN).mkdir(parents=True)
            with self.assertRaises(SystemExit):
                runner.main(["--run-id", RUN, "--stages", "S01", "--evidence-root", str(root), "--start-utc", WINDOW["start_utc"]])


class D3RuntimeTests(unittest.TestCase):
    def _setup(self, temp, stages):
        root = Path(temp) / "evidence"
        directory = root / RUN
        directory.mkdir(parents=True)
        bundle = core.run_unit(RUN, stages, harness_allowed=True, start_utc=START)
        return root, directory, bundle

    def test_runtime_single_stage_validates(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            data = runtime_input(bundle, directory, RUN)
            result = collect.assemble(data, root, ROOT)
            self.assertIn("proof=runtime", result)
            self.assertIn("golden_chain=False", result)

    def test_runtime_multi_stage_validates(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S07", "S09"])
            data = runtime_input(bundle, directory, RUN)
            self.assertIn("2 stage(s)", collect.assemble(data, root, ROOT))

    def test_runtime_all_stages_never_counts_as_d4_golden(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            directory = root / RUN
            directory.mkdir(parents=True)
            bundle = core.run_unit(RUN, list(core.STAGE_ORDER), harness_allowed=False, start_utc=START)
            result = collect.assemble(runtime_input(bundle, directory, RUN), root, ROOT)
            manifest = json.loads((directory / "run-manifest.json").read_text())
            self.assertFalse(manifest["counts_toward_golden_chain"])
            self.assertIn("golden_chain=False", result)

    def test_every_runtime_source_requires_native_shape(self):
        cases = {"alb_access": "S01", "nginx_modsecurity": "S02", "auditd": "S05", "flow_logs": "S08", "cloudtrail": "S06", "s3_data_event": "S07", "rds_audit": "S09"}
        for source, stage in cases.items():
            with self.subTest(source=source), tempfile.TemporaryDirectory() as temp:
                root, directory, bundle = self._setup(temp, [stage])
                data = runtime_input(bundle, directory, RUN, source_override=source)
                self.assertIn("proof=runtime", collect.assemble(data, root, ROOT))

    def test_runtime_rejects_app_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            data = runtime_input(bundle, directory, RUN, source_override="web")
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            data = runtime_input(bundle, directory, RUN, corrupt=True)
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_raw_secret_rejected_after_valid_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            data = runtime_input(bundle, directory, RUN)
            descriptor = data["observations"]["S06"]["runtime_sources"][0]
            raw_path = directory / descriptor["evidence_path"]
            item = json.loads(raw_path.read_text())
            item["Records"][0]["leak"] = "AKIAABCDEFGHIJKLMNOP"
            raw_path.write_text(json.dumps(item, separators=(",", ":")), encoding="utf-8")
            descriptor["content_sha256"] = hashlib.sha256(raw_path.read_bytes()).hexdigest()
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_wrong_cloudtrail_operation_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            data = runtime_input(bundle, directory, RUN)
            descriptor = data["observations"]["S06"]["runtime_sources"][0]
            raw_path = directory / descriptor["evidence_path"]
            item = json.loads(raw_path.read_text())
            item["Records"][0]["eventName"] = "ListBuckets"
            raw_path.write_text(json.dumps(item, separators=(",", ":")), encoding="utf-8")
            descriptor["content_sha256"] = hashlib.sha256(raw_path.read_bytes()).hexdigest()
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_missing_anchor_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            data = runtime_input(bundle, directory, RUN)
            data["observations"]["S06"]["runtime_sources"][0]["anchors"].append("ABSENT-ANCHOR")
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            data = runtime_input(bundle, directory, RUN)
            data["observations"]["S06"]["runtime_sources"][0]["evidence_path"] = "../escape.log"
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_manifest_without_window_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            collect.assemble(runtime_input(bundle, directory, RUN), root, ROOT)
            manifest = json.loads((directory / "run-manifest.json").read_text())
            del manifest["run_window"]
            (directory / "run-manifest.json").write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_runtime_collector_refuses_existing_derived_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            data = runtime_input(bundle, directory, RUN)
            collect.assemble(data, root, ROOT)
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_synthetic_with_runtime_sources_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            directory = root / RUN
            directory.mkdir(parents=True)
            bundle = core.run_unit(RUN, ["S06"], harness_allowed=True, start_utc=START)
            directory.joinpath("run-manifest.json").write_text(json.dumps(bundle["manifest"], separators=(",", ":"), sort_keys=True))
            directory.joinpath("provenance.json").write_text(json.dumps(runner.build_provenance(RUN), separators=(",", ":"), sort_keys=True))
            events = bundle["events"]
            events[0]["runtime_sources"] = [{"source": "cloudtrail"}]
            runner.write_jsonl(directory / "events.jsonl", events)
            runner.write_jsonl(directory / "handoffs.jsonl", bundle["handoffs"])
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_gate_plan_only_and_require_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, bundle = self._setup(temp, ["S06"])
            # runtime evidence in place -> plan-only must reject, require-runtime accepts
            collect.assemble(runtime_input(bundle, directory, RUN), root, ROOT)
            with self.assertRaises(SystemExit):
                gate.main(["--evidence-root", str(root), "--run-id", RUN, "--plan-only"])
            gate.main(["--evidence-root", str(root), "--run-id", RUN, "--require-runtime"])

    def test_gate_plan_only_accepts_synthetic(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _, _ = materialize(temp, RUN, ["S06"], harness=True)
            gate.main(["--evidence-root", str(root), "--run-id", RUN, "--plan-only"])
            with self.assertRaises(SystemExit):
                gate.main(["--evidence-root", str(root), "--run-id", RUN, "--require-runtime"])


if __name__ == "__main__":
    unittest.main()
