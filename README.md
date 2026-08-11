# ARGUS D0A-LOCAL

This is an authorized, isolated, localhost-only Docker Compose lab for the local pre-D5 proof:

`S02 fixed synthetic SQLi-class auth -> S03 verifiable administrator session -> S04 administrator-only fixed marker`

It is not an AWS run, not a full S01-S10 chain, and not a HybridNB model experiment. It contains no real accounts or data, accepts no external SQL text, and exposes no command execution, upload, shell, credential extraction, C2, external target, or destructive API. The only S04 effect is writing a bounded JSON marker to `./evidence/<run_id>/marker.json`.

## Boundaries and topology

The only published listener is `127.0.0.1:18080`. The Compose networks are intentionally segmented:

```text
localhost -> ingress bridge -> Gateway -> edge (internal) -> Web -> app (internal) -> WAS -> data (internal) -> MySQL
```

Only Gateway joins the non-internal `ingress` bridge. It also joins the internal `edge` network to reach Web. Web, WAS, and MySQL join internal networks only; the explicit `127.0.0.1:18080:8080` publishing rule and ingress bridge host-binding option retain localhost-only inbound access.

The gateway's raw, independently generated Nginx/CRS request tap is `evidence/waf-request-tap.jsonl`; ModSecurity audit output is `evidence/modsecurity-audit.log`. The HybridNB adapter instead receives its own versioned envelope made from the original Web request (`schemas/hybridnb-request-envelope-v1.json`). It is fixed to `disabled_not_evaluated`; it consumes neither CRS action, rule ID, nor anomaly score. D5, not this directory, owns real model loading and the four-quadrant experiment.

MySQL has three synthetic rows, below the ten-row limit. All base images and the MySQL image are digest-pinned; the runner records resolved built-image IDs plus seed/fixture/schema hashes. Request, response/event, and marker records are limited to 32 KiB. `fixtures/d0a-local-fixtures.json` contains only fixture tokens: the externally supplied request never contains SQL text.

## Run contract and evidence

Only a frozen run identifier is accepted:

```text
ARGUS-YYYYMMDD-LOCAL-RNN
```

The runner writes the exact approved local manifest before startup. A client header is only a correlation field; it cannot approve a run. WAS checks the manifest before doing either fixed action. MySQL's runtime `argus_auth_reader` is granted only `SELECT` on the synthetic auth table; Web has no database dependency or database network route.

The event schema uses the common names `evidence_id`, `event_time_utc`, and `stage_id` in `schemas/event-v1.json`. Correlations are deliberately exact:

```text
S02 auth_decision_hash
  -> S03 admin_session_hash + one-time TTL upload_ticket_id
  -> S04 web_marker_sha256 + web_action_context_id
```

`upload_ticket_id` is a compatibility name for the one-time Web capability ticket only. There is no upload endpoint or upload operation.

## Prerequisites

- Docker Desktop or another Docker engine available through `docker`.
- PowerShell and Python 3 on the host.

No system package, external deployment, account, or non-synthetic secret is needed. The MySQL root and runtime-reader values are fixed, obvious local synthetic credentials; `.env.example` only permits changing the synthetic database name, root password, and evidence path. Do not place real credentials in `.env`.

## Static checks (Docker not required)

```powershell
python scripts/validate_static.py
python -m unittest tests/test_d0a_contract.py
```

These parse the Python and JSON artifacts, check topology/limits/DB boundary, validate frozen run IDs and manifest approval, and test session and disabled-HybridNB contract helpers.

After building the gateway image on a Docker-capable host, validate its read-only Nginx configuration before starting the scenario:

```powershell
docker run --rm --read-only --network none --add-host web:127.0.0.1 `
  --tmpfs /evidence --tmpfs /var/cache/nginx --tmpfs /var/run `
  argus-d0a-local-gateway:latest nginx -t
```

The gateway uses a 32 KiB proxy buffer size, four such buffers, and an explicit 64 KiB busy-buffer limit. All Nginx temp paths initialized by `nginx -t` (`client_body_temp_path`, `proxy_temp_path`, `fastcgi_temp_path`, `uwsgi_temp_path`, and `scgi_temp_path`) are under the `/var/cache/nginx` tmpfs mounted by this command; proxy temp-file writes are disabled. This is a valid Nginx buffer relationship, and the separate 32 KiB application response/evidence contract remains unchanged.

## Start, verify, and teardown

From this directory on a Docker-capable host:

```powershell
.\scripts\run-d0a.ps1
```

The runner enforces a minimum one-second gap between all HTTP requests and sends no concurrent request (1 rps, concurrency 1). It then:

1. Validates the static contract and creates the approved local run manifest.
2. Starts a clean Compose database seed (`docker compose down --volumes` affects only this named Compose stack and its named DB volume, never source or evidence files).
3. Asserts `docker compose port gateway 8080` resolves to `127.0.0.1:18080` and preserves that result before any scenario request.
4. Records built service image IDs plus MySQL seed, fixture, and schema SHA-256 hashes in task-local evidence; then proves S02/S03/S04 correlations and the fixed marker contents.
5. Proves invalid `run_id` returns HTTP 400 and an unauthenticated marker request returns HTTP 401.
6. Validates the JSONL event chain, disabled HybridNB evidence, WAF request tap, and marker hash.
7. Stops/removes only this Compose stack and its named database volume in `finally`; it preserves `evidence/`.

If build, startup, health polling, or scenario validation fails, the runner retains the new run directory and writes `failure.json`, `compose-ps.txt`, and `compose-logs.txt` there before cleanup. A health timeout also records `gateway-health-last-error.txt`. It never appends to or overwrites a prior run directory.

To inspect an already completed run manually:

```powershell
python scripts/validate_evidence.py --evidence-root evidence --run-id ARGUS-20260811-LOCAL-R01
Get-Content evidence\ARGUS-20260811-LOCAL-R01\marker.json
```

## Stop conditions

Stop immediately and do not broaden the lab if any of these occurs:

- Docker is absent, its engine is unavailable, or image/build retrieval fails.
- A listener is not bound exclusively to localhost.
- A run lacks the exact approved manifest, fails the frozen identifier form, exceeds 1 rps/concurrency 1, exceeds 32 KiB, or has more than ten synthetic rows.
- S02/S03/S04 event hashes or ticket/context bindings do not correlate.
- The disabled HybridNB adapter consumes any CRS-derived output.
- A proposed change introduces arbitrary SQL input, commands, uploads, shells, credential extraction, C2, external targets, write/delete APIs, or any effect outside task-local evidence.

At a stop condition, preserve the current evidence and use `docker compose down --volumes --remove-orphans` only for this local stack after investigation.
