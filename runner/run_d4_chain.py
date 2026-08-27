"""D4-FULL-CHAIN local synthetic runner. It performs no AWS calls, no network
I/O, and no attack replay. It produces the local synthetic full-chain evidence
bundle for the complete S01->S10 chain with NO approval-harness injection, so it
proves the end-to-end contract locally but can never be a golden chain
(proof_kind=local_synthetic). Runtime golden chains come from collect_d4_runtime.

Usage:

  python runner/run_d4_chain.py --run-id ARGUS-20260827-BASE-R01 \
      --evidence-root evidence --start-utc 2026-08-27T00:00:00Z
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "scripts"))
import d3_core  # noqa: E402
import d4_core  # noqa: E402
import validate_d4_evidence  # noqa: E402


def sha_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_provenance(run_id):
    return validate_d4_evidence.expected_provenance(ROOT, run_id)


def write_new_text(path, content):
    try:
        with path.open("x", encoding="utf-8", newline="") as stream:
            stream.write(content)
    except FileExistsError as exc:
        raise d4_core.D4Error("evidence artifact already exists: " + str(path)) from exc


def write_jsonl(path, rows):
    write_new_text(path, "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--evidence-root", default="evidence")
    parser.add_argument("--start-utc", default=None, help="UTC start, e.g. 2026-08-27T00:00:00Z")
    args = parser.parse_args(argv)

    if args.start_utc:
        start = d3_core.parse_utc(args.start_utc)
    else:
        start = datetime.now(timezone.utc).replace(microsecond=0)

    try:
        bundle = d4_core.run_chain(args.run_id, start_utc=start)
    except d3_core.D3Error as exc:
        raise SystemExit("D4 chain runner rejected: " + str(exc)) from exc

    evidence_root = Path(args.evidence_root)
    directory = evidence_root / args.run_id
    try:
        directory.mkdir(parents=True, exist_ok=False)
        write_new_text(directory / "run-manifest.json", json.dumps(bundle["manifest"], separators=(",", ":"), sort_keys=True))
        write_new_text(directory / "provenance.json", json.dumps(build_provenance(args.run_id), separators=(",", ":"), sort_keys=True))
        write_jsonl(directory / "events.jsonl", bundle["events"])
        write_jsonl(directory / "handoffs.jsonl", bundle["handoffs"])
    except (FileExistsError, d3_core.D3Error) as exc:
        raise SystemExit("D4 chain runner rejected: evidence run id is immutable; use a new run id (" + str(exc) + ")") from exc

    result = validate_d4_evidence.validate(evidence_root, args.run_id, ROOT)
    print(result)
    print("D4 local synthetic full-chain evidence written to " + str(directory) + "; no AWS call or attack fixture was executed")
    print("NOTE: proof_kind=local_synthetic can never be a golden chain; run collect_d4_runtime against live-BASE evidence for the golden chain")


if __name__ == "__main__":
    main()
