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
    for run_id in run_ids:
        core.validate_run_id(run_id)
        manifest = d4v.read_json(root / run_id / "run-manifest.json", "run manifest")
        if manifest.get("proof_kind") != "runtime":
            raise d4.D4Error(run_id + " is not a runtime run; only runtime golden chains form the baseline")
        # Independent per-run re-validation; never trust the manifest flag alone.
        d4v.validate(root, run_id, checkout)
        if manifest.get("counts_toward_golden_chain") is not True:
            raise d4.D4Error(run_id + " is not a golden chain")
    return {
        "manifest_version": d4.SCHEMA_BASELINE,
        "scenario": d4.SCENARIO,
        "experiment_group": d4.EXPERIMENT_GROUP,
        "golden_chain_runs": list(run_ids),
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
