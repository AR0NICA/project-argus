import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "scripts"))

# Import by name (not importlib file-loading) so every module shares one d3_core
# instance; otherwise the validator's D3Error class would differ from this test's.
import d3_core as core  # noqa: E402
import d4_core as d4  # noqa: E402
import validate_d3_evidence as d3v  # noqa: E402
import validate_d4_evidence as validator  # noqa: E402
import run_d4_chain as runner  # noqa: E402
import collect_d4_runtime as collect  # noqa: E402
import run_d4_gate as gate  # noqa: E402
import validate_d4_baseline as baseline  # noqa: E402

RUN = "ARGUS-20260827-BASE-R01"
START = core.parse_utc("2026-08-27T00:00:00Z")
WINDOW = {"start_utc": "2026-08-27T00:00:00Z", "end_utc": "2026-08-27T01:00:00Z"}


def make_source(directory, stage, run_id, event_time_utc, source=None, corrupt=False):
    src = source if source is not None else sorted(d3v.RUNTIME_SOURCES[stage])[0]
    run_digest = hashlib.sha256((run_id + ":" + stage).encode("utf-8")).hexdigest()
    if src in {"cloudtrail", "s3_data_event"}:
        native = "%s-%s-4%s-8%s-%s" % (run_digest[:8], run_digest[8:12], run_digest[13:16], run_digest[17:20], run_digest[20:32])
        event_name = "GetCallerIdentity" if stage == "S06" else "GetObject"
        event_source = "sts.amazonaws.com" if stage == "S06" else "s3.amazonaws.com"
        item = {"eventID": native, "eventTime": event_time_utc, "eventSource": event_source, "eventName": event_name}
        if stage == "S07":
            item["requestParameters"] = {"key": "canary.txt", "versionId": "version-01"}
        text = json.dumps({"Records": [item]}, separators=(",", ":"))
    elif src == "flow_logs":
        native = "eni-" + run_digest[:12]
        epoch = int(core.parse_utc(event_time_utc).timestamp())
        text = "2 123456789012 %s 10.0.1.10 10.0.2.20 51000 443 6 1 128 %d %d ACCEPT OK" % (native, epoch - 1, epoch + 1)
    elif src == "alb_access":
        native = "Root=1-%s-%s" % (run_digest[:8], run_digest[8:32])
        text = 'https %s app/argus/123 10.0.0.1:443 10.0.1.1:8080 0 0 0 200 200 1 1 "GET / HTTP/1.1" "test" - - arn "-" "-" 0 %s' % (event_time_utc, native)
    elif src == "auditd":
        epoch = core.parse_utc(event_time_utc).timestamp()
        native = "audit(%.3f:%d)" % (epoch, int(run_digest[:6], 16))
        text = "type=SYSCALL msg=%s arch=c000003e syscall=1 success=yes" % native
    elif src == "nginx_modsecurity":
        native = "NGINX-REQ-" + run_digest[:16]
        text = json.dumps({"source": "nginx", "event_time_utc": event_time_utc, "request_id": native}, separators=(",", ":"))
    elif src == "rds_audit":
        native = "RDS-THREAD-" + run_digest[:16]
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


def runtime_input(bundle, directory, run_id, source_override=None, corrupt=False, inject=None):
    observations = {}
    stages = []
    for event in bundle["events"]:
        if not event["evidence_id"].endswith("-E01"):
            continue
        stage = event["stage_id"]
        stages.append(stage)
        record = make_source(directory, stage, run_id, event["event_time_utc"], source=source_override, corrupt=corrupt)
        obs = {"event_time_utc": event["event_time_utc"], "success_token_kind": event["success_token_kind"], "success_token_value": event["success_token_value"], "content_sha256": event["content_sha256"], "handoff_in_id": event["handoff_in_id"], "handoff_out_id": event["handoff_out_id"], "harness_injected": False, "runtime_sources": [record]}
        if stage in ("S09", "S10"):
            obs["result_guard"] = event["result_guard"]
        if "request_count" in event:
            obs["request_count"] = event["request_count"]
        if inject and stage == inject:
            obs["harness_injected"] = True
        observations[stage] = obs
    return {"input_version": collect.INPUT_VERSION, "run_id": run_id, "run_window": WINDOW, "stages": stages, "observations": observations, "handoffs": bundle["handoffs"]}


def materialize_local(temp, run_id):
    bundle = d4.run_chain(run_id, start_utc=START)
    root = Path(temp) / "evidence"
    directory = root / run_id
    directory.mkdir(parents=True)
    directory.joinpath("run-manifest.json").write_text(json.dumps(bundle["manifest"], separators=(",", ":"), sort_keys=True))
    directory.joinpath("provenance.json").write_text(json.dumps(runner.build_provenance(run_id), separators=(",", ":"), sort_keys=True))
    runner.write_jsonl(directory / "events.jsonl", bundle["events"])
    runner.write_jsonl(directory / "handoffs.jsonl", bundle["handoffs"])
    return root, directory, bundle


def build_golden(root, run_id):
    directory = root / run_id
    directory.mkdir(parents=True)
    bundle = d4.run_chain(run_id, start_utc=START)
    data = runtime_input(bundle, directory, run_id)
    return collect.assemble(data, root, ROOT)


def rewrite_jsonl(path, rows):
    path.write_text("".join(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in rows))


class D4EngineTests(unittest.TestCase):
    def test_golden_eligibility_rule(self):
        full = list(core.STAGE_ORDER)
        self.assertTrue(d4.golden_eligibility("runtime", full, [])["counts_toward_golden_chain"])
        self.assertFalse(d4.golden_eligibility("local_synthetic", full, [])["counts_toward_golden_chain"])
        self.assertFalse(d4.golden_eligibility("runtime", full[:9], [])["counts_toward_golden_chain"])
        self.assertFalse(d4.golden_eligibility("runtime", full, ["db_read_ticket_id"])["counts_toward_golden_chain"])

    def test_run_chain_is_full_uninjected_and_not_golden(self):
        bundle = d4.run_chain(RUN, start_utc=START)
        self.assertEqual(bundle["manifest"]["stages_executed"], list(core.STAGE_ORDER))
        self.assertEqual(bundle["manifest"]["harness_injected_handoffs"], [])
        self.assertFalse(bundle["manifest"]["counts_toward_golden_chain"])
        self.assertTrue(all(not h["harness_injected"] for h in bundle["handoffs"]))

    def test_run_chain_rejects_bad_run_id(self):
        with self.assertRaises(core.D3Error):
            d4.run_chain("not-a-run-id", start_utc=START)


class D4LocalEvidenceTests(unittest.TestCase):
    def test_local_full_chain_validates_but_not_golden(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _, _ = materialize_local(temp, RUN)
            result = validator.validate(root, RUN, ROOT)
            self.assertIn("golden_chain=False", result)
            self.assertIn("10 stage(s)", result)

    def test_local_forged_golden_flag_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            manifest = json.loads((directory / "run-manifest.json").read_text())
            manifest["counts_toward_golden_chain"] = True  # synthetic can never be golden
            (directory / "run-manifest.json").write_text(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_incomplete_chain_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            events = [e for e in events if e["stage_id"] != "S10"]
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_injected_event_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            events[0]["harness_injected"] = True
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_injected_handoff_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            handoffs = [json.loads(x) for x in (directory / "handoffs.jsonl").read_text().splitlines()]
            handoffs[0]["harness_injected"] = True
            handoffs[0]["issued_by_stage"] = "harness"
            rewrite_jsonl(directory / "handoffs.jsonl", handoffs)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_forged_handoff_in_id_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            for event in events:
                if event["stage_id"] == "S07" and event["evidence_id"].endswith("-E01"):
                    event["handoff_in_id"] = "11111111-1111-4111-8111-111111111111"
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_broken_chain_binding_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            handoffs = [json.loads(x) for x in (directory / "handoffs.jsonl").read_text().splitlines()]
            for record in handoffs:  # detach a token from its issuing stage success token
                record["predecessor_success_token"] = "f" * 64
            rewrite_jsonl(directory / "handoffs.jsonl", handoffs)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_forged_terminal_success_token_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            for event in events:
                if event["stage_id"] == "S10":
                    event["success_token_value"] = "0" * 64
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_cross_stage_allowed_action_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            for event in events:
                if event["stage_id"] == "S05":
                    event["action"] = "MARKER"  # globally allowed, but only frozen for S04
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_orphan_handoff_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            handoffs = [json.loads(x) for x in (directory / "handoffs.jsonl").read_text().splitlines()]
            orphan = dict(handoffs[0])
            orphan["handoff_id"] = "11111111-1111-4111-8111-111111111111"
            handoffs.append(orphan)
            rewrite_jsonl(directory / "handoffs.jsonl", handoffs)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_handoff_predecessor_kind_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            handoffs = [json.loads(x) for x in (directory / "handoffs.jsonl").read_text().splitlines()]
            handoffs[0]["predecessor_success_kind"] = "event_id"
            rewrite_jsonl(directory / "handoffs.jsonl", handoffs)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_handoff_event_timestamp_detachment_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            handoffs = [json.loads(x) for x in (directory / "handoffs.jsonl").read_text().splitlines()]
            handoffs[0]["issued_at_utc"] = "2026-08-26T23:59:59Z"
            handoffs[0]["not_after_utc"] = "2026-08-27T00:01:59Z"
            rewrite_jsonl(directory / "handoffs.jsonl", handoffs)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_oversize_result_guard_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            for event in events:
                if event["stage_id"] == "S09" and event["evidence_id"].endswith("-E01"):
                    event["result_guard"]["row_count"] = 11
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_timestamp_spacing_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            first = events[0]["event_time_utc"]
            for event in events:
                if event["stage_id"] == "S02" and event["evidence_id"].endswith("-E01"):
                    event["event_time_utc"] = first
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_provenance_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            provenance = json.loads((directory / "provenance.json").read_text())
            provenance["d4_core_sha256"] = "0" * 64
            (directory / "provenance.json").write_text(json.dumps(provenance, separators=(",", ":"), sort_keys=True))
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_s01_over_budget_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            events[0]["request_count"] = core.S01_MAX_REQUESTS + 1
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_s02_adapter_freeze_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            for event in events:
                if event.get("event_type") == "hybridnb_adapter":
                    event["correlation"]["evaluation_status"] = "blocked"
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_model_score_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            events[0]["correlation"]["model_score"] = 0.99
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_secret_leak_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            events[0]["correlation"]["leak"] = "AKIAABCDEFGHIJKLMNOP"
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_extra_event_per_stage_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root, directory, _ = materialize_local(temp, RUN)
            events = [json.loads(x) for x in (directory / "events.jsonl").read_text().splitlines()]
            extra = dict(events[0])
            extra["evidence_id"] = "%s-S01-E02" % RUN
            events.append(extra)
            rewrite_jsonl(directory / "events.jsonl", events)
            with self.assertRaises(core.D3Error):
                validator.validate(root, RUN, ROOT)

    def test_runner_refuses_existing_run_id(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            (root / RUN).mkdir(parents=True)
            with self.assertRaises(SystemExit):
                runner.main(["--run-id", RUN, "--evidence-root", str(root), "--start-utc", WINDOW["start_utc"]])


class D4RuntimeTests(unittest.TestCase):
    def test_runtime_full_chain_is_golden(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            result = build_golden(root, RUN)
            self.assertIn("proof=runtime", result)
            self.assertIn("golden_chain=True", result)

    def test_runtime_partial_input_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            directory = root / RUN
            directory.mkdir(parents=True)
            bundle = d4.run_chain(RUN, start_utc=START)
            data = runtime_input(bundle, directory, RUN)
            data["stages"] = data["stages"][:9]
            data["observations"].pop("S10", None)
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_injected_observation_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            directory = root / RUN
            directory.mkdir(parents=True)
            bundle = d4.run_chain(RUN, start_utc=START)
            data = runtime_input(bundle, directory, RUN, inject="S06")
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_app_source_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            directory = root / RUN
            directory.mkdir(parents=True)
            bundle = d4.run_chain(RUN, start_utc=START)
            data = runtime_input(bundle, directory, RUN)
            data["observations"]["S06"]["runtime_sources"][0]["source"] = "web_app"
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            directory = root / RUN
            directory.mkdir(parents=True)
            bundle = d4.run_chain(RUN, start_utc=START)
            data = runtime_input(bundle, directory, RUN, corrupt=True)
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_runtime_missing_window_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            directory = root / RUN
            directory.mkdir(parents=True)
            bundle = d4.run_chain(RUN, start_utc=START)
            data = runtime_input(bundle, directory, RUN)
            del data["run_window"]
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)

    def test_collector_refuses_existing_derived(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            build_golden(root, RUN)
            directory = root / RUN
            bundle = d4.run_chain(RUN, start_utc=START)
            data = runtime_input(bundle, directory, RUN)
            with self.assertRaises(core.D3Error):
                collect.assemble(data, root, ROOT)


class D4GateTests(unittest.TestCase):
    def test_gate_plan_only_accepts_synthetic(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _, _ = materialize_local(temp, RUN)
            gate.main(["--evidence-root", str(root), "--run-id", RUN, "--plan-only"])

    def test_gate_require_runtime_rejects_synthetic(self):
        with tempfile.TemporaryDirectory() as temp:
            root, _, _ = materialize_local(temp, RUN)
            with self.assertRaises(SystemExit):
                gate.main(["--evidence-root", str(root), "--run-id", RUN, "--require-runtime"])

    def test_gate_require_runtime_accepts_golden(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            build_golden(root, RUN)
            gate.main(["--evidence-root", str(root), "--run-id", RUN, "--require-runtime"])

    def test_gate_plan_only_rejects_runtime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            build_golden(root, RUN)
            with self.assertRaises(SystemExit):
                gate.main(["--evidence-root", str(root), "--run-id", RUN, "--plan-only"])


class D4BaselineTests(unittest.TestCase):
    RUNS = ["ARGUS-20260827-BASE-R01", "ARGUS-20260827-BASE-R02", "ARGUS-20260827-BASE-R03"]

    def test_three_golden_establishes_baseline(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            for run_id in self.RUNS:
                build_golden(root, run_id)
            manifest = baseline.assemble_baseline(root, self.RUNS, ROOT)
            self.assertTrue(manifest["baseline_established"])
            self.assertEqual(manifest["golden_chain_count"], 3)
            self.assertEqual([member["run_id"] for member in manifest["golden_chain_members"]], self.RUNS)
            for member in manifest["golden_chain_members"]:
                for key in ("run_manifest_sha256", "provenance_sha256", "events_sha256", "handoffs_sha256"):
                    self.assertRegex(member[key], core.SHA_RE)

    def test_native_record_reused_across_runs_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            for run_id in self.RUNS:
                build_golden(root, run_id)

            source_directory = root / self.RUNS[0]
            target_directory = root / self.RUNS[1]
            source_events = [json.loads(x) for x in (source_directory / "events.jsonl").read_text().splitlines()]
            target_events = [json.loads(x) for x in (target_directory / "events.jsonl").read_text().splitlines()]
            source_record = next(event for event in source_events if event["stage_id"] == "S01")["runtime_sources"][0]
            target_event = next(event for event in target_events if event["stage_id"] == "S01")
            target_event["runtime_sources"] = [json.loads(json.dumps(source_record))]
            target_raw = target_directory / source_record["evidence_path"]
            target_raw.write_bytes((source_directory / source_record["evidence_path"]).read_bytes())
            rewrite_jsonl(target_directory / "events.jsonl", target_events)

            # The member still validates alone; only the aggregate independence
            # rule rejects reusing a source-native record in another run.
            validator.validate(root, self.RUNS[1], ROOT)
            with self.assertRaises(core.D3Error):
                baseline.assemble_baseline(root, self.RUNS, ROOT)

    def test_fewer_than_three_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            for run_id in self.RUNS[:2]:
                build_golden(root, run_id)
            with self.assertRaises(core.D3Error):
                baseline.assemble_baseline(root, self.RUNS[:2], ROOT)

    def test_duplicate_run_ids_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            build_golden(root, self.RUNS[0])
            with self.assertRaises(core.D3Error):
                baseline.assemble_baseline(root, [self.RUNS[0], self.RUNS[0], self.RUNS[0]], ROOT)

    def test_synthetic_member_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            build_golden(root, self.RUNS[0])
            build_golden(root, self.RUNS[1])
            # third member is local synthetic, not a golden runtime chain
            bundle = d4.run_chain(self.RUNS[2], start_utc=START)
            directory = root / self.RUNS[2]
            directory.mkdir(parents=True)
            directory.joinpath("run-manifest.json").write_text(json.dumps(bundle["manifest"], separators=(",", ":"), sort_keys=True))
            directory.joinpath("provenance.json").write_text(json.dumps(runner.build_provenance(self.RUNS[2]), separators=(",", ":"), sort_keys=True))
            runner.write_jsonl(directory / "events.jsonl", bundle["events"])
            runner.write_jsonl(directory / "handoffs.jsonl", bundle["handoffs"])
            with self.assertRaises(core.D3Error):
                baseline.assemble_baseline(root, self.RUNS, ROOT)


if __name__ == "__main__":
    unittest.main()
