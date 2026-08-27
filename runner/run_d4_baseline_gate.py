"""D4 R1-BASELINE aggregate gate. It performs no AWS calls and replays nothing.

It binds three or more independent golden chains (distinct run ids), re-validating
each with the closed-world D4 per-run validator, and reports the R1 baseline. With
--write-manifest it also persists an immutable aggregate manifest under
<evidence-root>/<baseline-id>/r1-baseline-manifest.json.

Usage:
  python runner/run_d4_baseline_gate.py --evidence-root evidence \
      --run-id ARGUS-20260827-BASE-R01 \
      --run-id ARGUS-20260827-BASE-R02 \
      --run-id ARGUS-20260827-BASE-R03 \
      [--write-manifest --baseline-id ARGUS-20260827-BASE-R1BASELINE]
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "scripts"))
import d3_core as core  # noqa: E402
import validate_d4_baseline as baseline  # noqa: E402
import run_d4_chain  # noqa: E402

BASELINE_ID_RE = re.compile(r"^ARGUS-[0-9]{8}-BASE-[A-Z0-9]+$")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", default="evidence")
    parser.add_argument("--run-id", action="append", required=True, help="repeat for each golden-chain run id")
    parser.add_argument("--write-manifest", action="store_true")
    parser.add_argument("--baseline-id", default=None, help="directory id for the persisted aggregate manifest")
    args = parser.parse_args(argv)

    try:
        manifest = baseline.assemble_baseline(args.evidence_root, args.run_id, ROOT)
    except core.D3Error as exc:
        raise SystemExit("R1-BASELINE gate rejected: " + str(exc)) from exc

    print("R1-BASELINE gate accepted: %d golden chains over distinct run ids %s" % (manifest["golden_chain_count"], ", ".join(manifest["golden_chain_runs"])))

    if args.write_manifest:
        if not args.baseline_id or not BASELINE_ID_RE.fullmatch(args.baseline_id):
            raise SystemExit("R1-BASELINE gate rejected: --write-manifest needs a valid --baseline-id")
        directory = Path(args.evidence_root) / args.baseline_id
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / "r1-baseline-manifest.json"
        try:
            run_d4_chain.write_new_text(target, json.dumps(manifest, separators=(",", ":"), sort_keys=True))
        except core.D3Error as exc:
            raise SystemExit("R1-BASELINE gate rejected: aggregate manifest is immutable (" + str(exc) + ")") from exc
        print("R1-BASELINE aggregate manifest written to " + str(target))

    print("no AWS call or attack fixture was executed by the gate")


if __name__ == "__main__":
    main()
