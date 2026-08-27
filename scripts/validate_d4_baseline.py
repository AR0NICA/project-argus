"""D4 R1-BASELINE aggregate validation.

R1-BASELINE binds N independent golden chains. It re-runs the closed-world D4
per-run validator over each run id, requires each to be a runtime golden chain
(proof_kind=runtime AND counts_toward_golden_chain=true), requires the run ids to
be distinct, and requires at least MIN_GOLDEN_RUNS (three) of them. It performs no
AWS calls and replays nothing. The aggregate never re-labels a per-run result:
every member must already stand on its own as a validated golden chain.
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
import validate_d4_evidence as d4v  # noqa: E402


def assemble_baseline(evidence_root, run_ids, checkout):
    if not isinstance(run_ids, (list, tuple)) or len(run_ids) < d4.MIN_GOLDEN_RUNS:
        raise d4.D4Error("R1-BASELINE requires at least %d golden runs" % d4.MIN_GOLDEN_RUNS)
    if len(set(run_ids)) != len(run_ids):
        raise d4.D4Error("R1-BASELINE run ids must be distinct")
    root = Path(evidence_root)
    native_record_owners = {}
    members = []
    for run_id in run_ids:
        core.validate_run_id(run_id)
        manifest = d4v.read_json(root / run_id / "run-manifest.json", "run manifest")
        if manifest.get("proof_kind") != "runtime":
            raise d4.D4Error(run_id + " is not a runtime run; only runtime golden chains form the baseline")
        # Independent per-run re-validation; never trust the manifest flag alone.
        d4v.validate(root, run_id, checkout)
        if manifest.get("counts_toward_golden_chain") is not True:
            raise d4.D4Error(run_id + " is not a golden chain")
        directory = root / run_id
        events = d4v.read_jsonl(directory / "events.jsonl", "events evidence")
        for event in events:
            for source_record in event.get("runtime_sources", []):
                # A source-local id such as an RDS thread id can legitimately
                # recur later. Treat the native record as the id + native time
                # + exported bytes, and reject only reuse of that exact record.
                identity = (source_record["source"], source_record["native_record_id"], source_record["event_time_utc"], source_record["content_sha256"])
                owner = native_record_owners.get(identity)
                if owner is not None and owner != run_id:
                    raise d4.D4Error("runtime native record reused across baseline runs: %s/%s at %s (%s, %s)" % (identity[0], identity[1], identity[2], owner, run_id))
                native_record_owners[identity] = run_id
        members.append({
            "run_id": run_id,
            "run_manifest_sha256": d4v.sha_file(directory / "run-manifest.json"),
            "provenance_sha256": d4v.sha_file(directory / "provenance.json"),
            "events_sha256": d4v.sha_file(directory / "events.jsonl"),
            "handoffs_sha256": d4v.sha_file(directory / "handoffs.jsonl"),
        })
    return {
        "manifest_version": d4.SCHEMA_BASELINE,
        "scenario": d4.SCENARIO,
        "experiment_group": d4.EXPERIMENT_GROUP,
        "golden_chain_runs": list(run_ids),
        "golden_chain_members": members,
        "golden_chain_count": len(run_ids),
        "minimum_required": d4.MIN_GOLDEN_RUNS,
        "baseline_established": True,
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", default="evidence")
    parser.add_argument("--run-id", action="append", required=True, help="repeat for each golden-chain run id")
    args = parser.parse_args(argv)
    try:
        manifest = assemble_baseline(args.evidence_root, args.run_id, ROOT)
    except core.D3Error as exc:
        raise SystemExit("R1-BASELINE rejected: " + str(exc)) from exc
    print(json.dumps(manifest, separators=(",", ":"), sort_keys=True))
    print("R1-BASELINE established: %d golden chains over distinct run ids" % manifest["golden_chain_count"])


if __name__ == "__main__":
    main()
