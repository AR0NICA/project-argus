"""D3 R0-UNIT gate. It performs no AWS calls and replays nothing.

--plan-only accepts the local synthetic contract fixture (proof_kind=local_synthetic)
and must never be recorded as D3 completion. --require-runtime accepts only
independently-exported runtime evidence (proof_kind=runtime) with per-stage
independent-source corroboration.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "scripts"))
import d3_core as core  # noqa: E402
import validate_d3_evidence  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", default="evidence")
    parser.add_argument("--run-id", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan-only", action="store_true")
    mode.add_argument("--require-runtime", action="store_true")
    args = parser.parse_args(argv)

    directory = Path(args.evidence_root) / args.run_id
    try:
        manifest = json.loads((directory / "run-manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit("D3 gate rejected: run manifest is not readable JSON") from exc

    proof_kind = manifest.get("proof_kind")
    try:
        if args.plan_only and proof_kind != "local_synthetic":
            raise core.D3Error("--plan-only requires proof_kind=local_synthetic")
        if args.require_runtime and proof_kind != "runtime":
            raise core.D3Error("--require-runtime requires proof_kind=runtime")
        result = validate_d3_evidence.validate(Path(args.evidence_root), args.run_id, ROOT)
    except core.D3Error as exc:
        raise SystemExit("D3 gate rejected: " + str(exc)) from exc

    print("D3 gate accepted: " + result)
    if args.plan_only:
        print("NOTE: local synthetic contract proof only; not D3 completion. Re-run with --require-runtime against live-BASE evidence.")
    print("no AWS call or attack fixture was executed by the gate")


if __name__ == "__main__":
    main()
