# BASE redeploy + D3 R0-UNIT runtime runbook

Purpose: rebuild the BASE stack from the fully torn-down state (SuHo's
2026-08-24 teardown), then run R0-UNIT against live BASE and close D3 with
`proof_kind=runtime` evidence.

This runbook drives real AWS spend on a shared account and executes live
attack-stage traffic. Run it from an operator terminal or a fresh session — the
offensive-context safety classifier blocks live AWS commands in this working
session. Nothing here is a `terraform apply` you should run from the skeleton
phase without a reviewed saved plan.

## 0. Preconditions (must all be true first)

- **Shared-account coordination.** The account `962419263587` is shared with
  SuHo/AR0NICA, who just tore BASE down. Confirm no live BASE stack exists and
  that a rebuild now is agreed. Check the VPC `Owner` tag before any action.
- **Protective flags already set** in `infra/base/terraform.tfvars`:
  `teardown_authorized=false`, `teardown_mode="protected"`, no
  `evidence_cleanup_authorized`, no `evidence_cross_review_reference`. Leave them.
- **Do not reuse old artifacts.** Delete/ignore the stale saved plans
  `infra/base/base.tfplan`, `destroy.tfplan`, `destroy2.tfplan`. Build fresh
  plans only.

## 1. Stale prerequisites the teardown removed (must be refreshed)

The teardown deleted the ECR images, the Image Builder AMI/snapshot, and the
canary object. These `terraform.tfvars` values are now **dead** and must be
re-derived during redeploy — do not reuse the old ones:

- `gateway_image_digest`, `web_image_digest`, `was_image_digest`, `seed_image_digest`
- `builder_parent_ami_id` (re-verify the pinned ECS AL2023 parent AMI still exists)
- `canary_object_version_id`

The backend state bucket `argus-terraform-state-...-962419263587` still exists
(state emptied), so `terraform -chdir=infra/base init` reattaches to it.

## 2. Preflight (read-only)

```powershell
$env:AWS_PROFILE = "PowerClaude"
aws sts get-caller-identity
aws configure get region   # expect ap-northeast-2
```

Confirm account `962419263587`, region `ap-northeast-2`, AZs `ap-northeast-2a`/`2c`,
hostname `argus-base.ar0nica.xyz`, approved test `/32` ready, and the USD 25
budget email ready (passed at apply time, never persisted).

## 3. Phase build (one phase at a time; review each saved plan before apply)

Advance `disabled -> network -> evidence -> image -> substrate -> attachments`.
Use `infra/scripts/Invoke-BasePlan.ps1` for saved plans and
`infra/scripts/Invoke-BaseApply.ps1` to apply a reviewed plan (it asks for the
budget email locally and requires explicit opt-in).

1. `deployment_phase="network"` — VPC, subnets, SGs, VPC endpoints. Confirm no
   NAT, no public Web/WAS IP, no SSH rule in the plan.
2. `deployment_phase="evidence"` — CloudTrail evidence, ALB access-log + KMS +
   log groups, and the four ECR repos. This must run before images exist.
3. **Publish images:** `infra/scripts/Publish-BaseImages.ps1` builds/pushes
   gateway, web, was, seed as `linux/amd64` and prints the **new digests**.
   Write those four digests into `terraform.tfvars`.
4. `deployment_phase="image"` — Image Builder builds the immutable runtime AMI
   from the pinned parent AMI (~20-40 min; transient public builder, no SSH/NAT).
5. `deployment_phase="substrate"` — ALB, private Web/WAS, RDS, canary S3.
   - Seed synthetic data: `infra/scripts/Invoke-BaseSyntheticSeed.ps1`
     (temporary seed IAM gate; removed before the D1 health gate).
   - Publish canary: `infra/scripts/Publish-BaseCanary.ps1` prints SHA-256 and
     the new immutable `VersionId`. Write that `canary_object_version_id` into
     `terraform.tfvars`.
6. `deployment_phase="attachments"` — ALB logging, VPC Flow Logs, RDS exports,
   host logs, app log destinations.

## 4. Re-establish D1 and D2 for the new deployment cycle

- **D1 benign runtime**: collect one real benign observation, then gate it:
  ```powershell
  python runner/collect_d1_runtime.py ...   # exports runtime manifest + raw
  python runner/run_d1_gate.py --manifest evidence/<run>/d1-runtime-manifest.json --require-runtime --evidence-root evidence/<run>/raw
  ```
- **D2 operational regression**: confirm each kill switch works and the
  independent evidence path still records with the app/EC2 role detached. Do not
  reopen the closed D2 document; prove the switches are usable in this cycle.

## 5. D3 R0-UNIT against live BASE

Run each stage S01-S10 at least once, within the safety boundary
(`docs/D3-UNIT-CONTRACT.md`): S01 <= 12 requests; others one contract + one
control request; <= 1 rps, concurrency 1; synthetic only; <= 10 rows / 32 KiB;
only `MARKER`/`IMDS_IDENTITY`/`WAS_AUTH`; S07 exact key+version GetObject only;
HybridNB stays `disabled_not_evaluated`.

For each unit stage the approval harness injects the missing predecessor handoff
(recorded, so the run is never a golden chain). For every stage, export at least
one **independent** source raw evidence (CloudTrail, VPC Flow Logs, RDS
audit/general, S3 data event, ALB access, Nginx/ModSecurity, auditd — never the
web/was app logs) into `<evidence-root>/<run_id>/raw/`.

Assemble and gate the runtime evidence (no AWS calls in these steps):

```powershell
python runner/collect_d3_runtime.py --input <runtime-input.json> --evidence-root evidence
python runner/run_d3_gate.py --evidence-root evidence --run-id ARGUS-<UTCDATE>-BASE-R<NN> --require-runtime
```

Use `fixtures/d3-runtime-input.example.json` as the input template. The gate
accepts only `proof_kind=runtime` with per-stage independent-source
corroboration; `--plan-only`/local-synthetic proof is never D3 completion.

## 6. Close-out

- Capture all raw evidence under `evidence/<run_id>/raw/` **during** the run,
  before any teardown (D2 was once held for shipping only a summary).
- Independent reviewer confirms per-stage success tokens, one-time TTL handoffs,
  and raw evidence. The stage implementer does not approve their own stage.
- No evidence cleanup or teardown before the CrossReviewRef is recorded.
- After cross-review, teardown uses the guarded scripts in `infra/README.md`
  order (evidence -> ECR -> Image Builder -> destroy -> backend), each requiring
  the cross-review reference and `-Execute`.

## Cost note

Live BASE runs RDS `db.t3.micro`, two `t3.small` EC2 hosts, an ALB, CloudTrail
management + scoped S3 data events, KMS, CloudWatch Logs, and S3. Budget alarm is
USD 25/month. The Image Builder builder instance is transient. Keep the test
window short and tear down after cross-review to bound spend.
