"""D3 R0-UNIT runner. It performs no AWS calls, no network I/O, and no attack
replay. It produces the local synthetic-contract evidence bundle for one or more
S01-S10 unit stages, enforcing the one-time handoff chain and the safety guards.

Usage (local synthetic contract proof):

  python runner/run_d3_unit.py --run-id ARGUS-20260824-BASE-R01 --stages all \
      --evidence-root evidence --start-utc 2026-08-24T00:00:00Z
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
import validate_d3_evidence  # noqa: E402


def sha_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_provenance(run_id):
    return {
        "run_id": run_id,
        "fixture_sha256": sha_file(ROOT / "fixtures/d3-unit-fixtures.json"),
        "event_schema_sha256": sha_file(ROOT / "schemas/d3-event-v1.json"),
        "handoff_schema_sha256": sha_file(ROOT / "schemas/d3-handoff-token-v1.json"),
        "manifest_schema_sha256": sha_file(ROOT / "schemas/d3-run-manifest-v1.json"),
        "core_sha256": sha_file(ROOT / "runner/d3_core.py"),
    }


def write_new_text(path, content):
    try:
        with path.open("x", encoding="utf-8", newline="") as stream:
            stream.write(content)
    except FileExistsError as exc:
        raise d3_core.D3Error("evidence artifact already exists: " + str(path)) from exc


def write_jsonl(path, rows):
    write_new_text(path, "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stages", default="all", help="'all' or comma-separated S01..S10")
    parser.add_argument("--evidence-root", default="evidence")
    parser.add_argument("--start-utc", default=None, help="UTC start, e.g. 2026-08-24T00:00:00Z")
    parser.add_argument("--no-harness", action="store_true", help="disable predecessor injection (chain mode)")
    args = parser.parse_args(argv)

    if args.stages.strip().lower() == "all":
        stages = list(d3_core.STAGE_ORDER)
    else:
        stages = [item.strip().upper() for item in args.stages.split(",") if item.strip()]
    if args.start_utc:
        start = d3_core.parse_utc(args.start_utc)
    else:
        start = datetime.now(timezone.utc).replace(microsecond=0)

    try:
        bundle = d3_core.run_unit(args.run_id, stages, harness_allowed=not args.no_harness, start_utc=start)
    except d3_core.D3Error as exc:
        raise SystemExit("D3 unit runner rejected: " + str(exc)) from exc

    evidence_root = Path(args.evidence_root)
    directory = evidence_root / args.run_id
    try:
        directory.mkdir(parents=True, exist_ok=False)
        write_new_text(directory / "run-manifest.json", json.dumps(bundle["manifest"], separators=(",", ":"), sort_keys=True))
        write_new_text(directory / "provenance.json", json.dumps(build_provenance(args.run_id), separators=(",", ":"), sort_keys=True))
        write_jsonl(directory / "events.jsonl", bundle["events"])
        write_jsonl(directory / "handoffs.jsonl", bundle["handoffs"])
    except (FileExistsError, d3_core.D3Error) as exc:
        raise SystemExit("D3 unit runner rejected: evidence run id is immutable; use a new run id (" + str(exc) + ")") from exc

    result = validate_d3_evidence.validate(evidence_root, args.run_id, ROOT)
    print(result)
    print("D3 unit evidence written to " + str(directory) + "; no AWS call or attack fixture was executed")


if __name__ == "__main__":
    main()
