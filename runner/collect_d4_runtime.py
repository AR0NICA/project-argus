"""Assemble a D4-FULL-CHAIN runtime golden-chain bundle from operator-exported
observations of one live BASE run.

This assembler performs NO AWS calls and fabricates nothing. It takes a runtime
input bundle exported from a single live BASE full-chain run (the observed
success tokens, the real one-time handoff ledger, and per-stage independent-source
raw-evidence descriptors), requires the complete uninjected S01->S10 chain, shapes
the proof_kind=runtime evidence bundle with counts_toward_golden_chain re-derived,
and then runs the closed-world D4 validator over it. The independent raw-evidence
files must already exist under the run directory; the assembler only references
and verifies them.

Usage:
  python runner/collect_d4_runtime.py --input <runtime-input.json> \
      --evidence-root evidence
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "scripts"))
import d3_core as core  # noqa: E402
import d4_core as d4  # noqa: E402
import validate_d4_evidence  # noqa: E402
import run_d4_chain  # noqa: E402

INPUT_VERSION = "argus.d4-runtime-input/v1"


def build_event(run_id, stage, obs, counts_golden):
    spec = core.SPEC[stage]
    for key in ("event_time_utc", "success_token_kind", "success_token_value", "content_sha256", "handoff_in_id", "handoff_out_id", "runtime_sources"):
        if key not in obs:
            raise d4.D4Error(stage + " observation is missing " + key)
    if obs.get("harness_injected"):
        raise d4.D4Error("the D4 chain forbids harness injection; " + stage + " observation is injected")
    if obs["success_token_kind"] != spec["success_type"]:
        raise d4.D4Error(stage + " observed success token kind mismatch")
    correlation = {"success_field": spec["success_field"]}
    if stage == "S09":
        correlation["db_query_id"] = "ARGUS-Q01"
    event = {
        "schema_version": d4.SCHEMA_EVENT,
        "evidence_id": "%s-%s-E01" % (run_id, stage),
        "event_time_utc": obs["event_time_utc"],
        "run_id": run_id,
        "stage_id": stage,
        "event_type": spec["event_type"],
        "result": spec["result"],
        "request_id": obs.get("request_id", "%s-%s-REQ" % (run_id, stage)),
        "source_ref": obs.get("source_ref", "test_terminal" if stage == "S01" else "argus_web"),
        "target_ref": obs.get("target_ref", "argus_was"),
        "action": obs.get("action", spec["action"] or "none"),
        "fixture_or_resource_id": spec["fixture"],
        "content_sha256": obs["content_sha256"],
        "collector": "d4-runtime-collector",
        "reviewer": None,
        "redaction_status": "runtime_independent_source",
        "secret_material_present": False,
        "success_token_kind": obs["success_token_kind"],
        "success_token_value": obs["success_token_value"],
        "handoff_in_id": obs["handoff_in_id"],
        "handoff_out_id": obs["handoff_out_id"],
        "handoff_injected": False,
        "harness_injected": False,
        "counts_toward_golden_chain": bool(counts_golden),
        "correlation": correlation,
        "runtime_sources": obs["runtime_sources"],
    }
    if stage in ("S09", "S10"):
        if "result_guard" not in obs:
            raise d4.D4Error(stage + " observation is missing result_guard")
        event["result_guard"] = obs["result_guard"]
    if stage == "S01":
        if "request_count" not in obs:
            raise d4.D4Error("S01 observation is missing request_count")
        core.guard_s01_requests(obs["request_count"])
        event["request_count"] = obs["request_count"]
    core.assert_no_secret(event)
    core.assert_hybridnb_frozen(event)
    return event


def build_adapter(run_id, obs, counts_golden):
    spec = core.SPEC["S02"]
    event = {
        "schema_version": d4.SCHEMA_EVENT,
        "evidence_id": "%s-S02-E02" % run_id,
        "event_time_utc": obs["event_time_utc"],
        "run_id": run_id,
        "stage_id": "S02",
        "event_type": "hybridnb_adapter",
        "result": "not_evaluated",
        "request_id": obs.get("request_id", "%s-S02-REQ" % run_id),
        "source_ref": "argus_web",
        "target_ref": "hybridnb_interface",
        "action": "none",
        "fixture_or_resource_id": spec["fixture"],
        "content_sha256": obs["content_sha256"],
        "collector": "d4-runtime-collector",
        "reviewer": None,
        "redaction_status": "runtime_independent_source",
        "secret_material_present": False,
        "success_token_kind": obs["success_token_kind"],
        "success_token_value": obs["success_token_value"],
        "handoff_in_id": obs["handoff_in_id"],
        "handoff_out_id": None,
        "handoff_injected": False,
        "harness_injected": False,
        "counts_toward_golden_chain": bool(counts_golden),
        "correlation": dict(core.HYBRIDNB_ADAPTER),
    }
    core.assert_no_secret(event)
    core.assert_hybridnb_frozen(event)
    return event


def assemble(data, evidence_root, checkout):
    if not isinstance(data, dict) or data.get("input_version") != INPUT_VERSION:
        raise d4.D4Error("runtime input version mismatch")
    run_id = data.get("run_id", "")
    core.validate_run_id(run_id)
    stages = data.get("stages")
    if not isinstance(stages, list) or list(stages) != list(d4.FULL_CHAIN):
        raise d4.D4Error("D4 runtime input must be the complete S01..S10 chain in order")
    if not isinstance(data.get("run_window"), dict):
        raise d4.D4Error("runtime input requires a run_window")
    observations = data.get("observations", {})
    handoffs = data.get("handoffs")
    if not isinstance(observations, dict) or not isinstance(handoffs, list):
        raise d4.D4Error("runtime input observations/handoffs invalid")

    # Golden eligibility is re-derived: the complete chain, uninjected, runtime.
    eligibility = d4.golden_eligibility("runtime", stages, [])
    counts_golden = eligibility["counts_toward_golden_chain"]

    events = []
    for stage in d4.FULL_CHAIN:
        if stage not in observations:
            raise d4.D4Error("missing observation for " + stage)
        obs = observations[stage]
        events.append(build_event(run_id, stage, obs, counts_golden))
        if stage == "S02":
            events.append(build_adapter(run_id, obs, counts_golden))

    manifest = d4.build_manifest(run_id, "runtime", list(d4.FULL_CHAIN), [], counts_golden, run_window=data["run_window"])

    directory = Path(evidence_root) / run_id
    if not directory.is_dir():
        raise d4.D4Error("runtime run directory is missing; place raw evidence under the run id first")
    targets = [directory / name for name in ("run-manifest.json", "provenance.json", "events.jsonl", "handoffs.jsonl")]
    existing = [str(path) for path in targets if path.exists()]
    if existing:
        raise d4.D4Error("runtime evidence is immutable; derived artifact already exists: " + ", ".join(existing))
    run_d4_chain.write_new_text(targets[0], json.dumps(manifest, separators=(",", ":"), sort_keys=True))
    run_d4_chain.write_new_text(targets[1], json.dumps(run_d4_chain.build_provenance(run_id), separators=(",", ":"), sort_keys=True))
    run_d4_chain.write_jsonl(targets[2], events)
    run_d4_chain.write_jsonl(targets[3], handoffs)
    return validate_d4_evidence.validate(Path(evidence_root), run_id, checkout)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--evidence-root", default="evidence")
    args = parser.parse_args(argv)
    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("runtime input is not valid JSON: " + str(exc)) from exc
    try:
        result = assemble(data, args.evidence_root, ROOT)
    except core.D3Error as exc:
        raise SystemExit("D4 runtime collector rejected: " + str(exc)) from exc
    print(result)
    print("D4 runtime golden-chain evidence assembled; no AWS call was made by the collector")


if __name__ == "__main__":
    main()
