"""D1 benign-only contract gate. It performs no AWS calls or request replay."""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "observability"))
from validate_d1_manifest import load, validate  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("--manifest", required=True)
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument("--plan-only", action="store_true")
mode.add_argument("--require-runtime", action="store_true")
parser.add_argument("--evidence-root")
args = parser.parse_args()
try:
    manifest = load(args.manifest)
    if args.plan_only and manifest.get("proof_kind") != "plan": raise ValueError("--plan-only requires proof_kind=plan")
    if args.require_runtime and manifest.get("proof_kind") != "runtime": raise ValueError("--require-runtime requires proof_kind=runtime")
    if args.require_runtime and not args.evidence_root: raise ValueError("--require-runtime requires --evidence-root")
    result = validate(manifest, args.evidence_root)
except ValueError as exc:
    raise SystemExit("D1 gate rejected: " + str(exc)) from exc
print("D1 gate accepted: " + result["proof_kind"] + " proof; no AWS call or attack fixture was executed")
