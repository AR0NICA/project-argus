# ARGUS infrastructure skeleton

This tree is the G1 implementation skeleton. It does not contain an approved
deployment configuration and must not be applied with placeholder values.

## State boundary

- `bootstrap/` is a deliberately separate, local-state root that creates only
  the BASE remote-state bucket. It must be applied and reviewed separately;
  `base/` never manages its own active backend bucket.
- `base/` uses `argus-terraform-state-ap-northeast-2-962419263587` with the
  `argus/base/terraform.tfstate` key, S3 lockfile, versioning, SSE-S3, public
  access block, and BucketOwnerEnforced ownership.
- `hardened/` uses the `argus/hardened/terraform.tfstate` backend key and
  `argus-hardened` resource prefix.
- HARDENED is never an in-place mutation of BASE.
- Per-control `argus/control/<control-id>` roots are deferred to D6.

## Frozen observability bucket names

The D1 evidence and ALB access-log bucket names are derived in each root from
the environment prefix, AWS region, and the single approved AWS account ID:

```text
argus-base-d1-evidence-<region>-<account-id>
argus-base-alb-access-<region>-<account-id>
argus-hardened-d1-evidence-<region>-<account-id>
argus-hardened-alb-access-<region>-<account-id>
```

They are not deployment inputs. This keeps BASE and HARDENED distinct across
separate states and gives every operator the same names. Changing this formula
is an explicit bucket migration and requires a reviewed state-aware plan. The
later canary bucket remains a separate substrate input and is not part of this
D1 naming contract.

## Frozen deployment order

1. State and safety guards.
2. VPC, subnets, security groups, and VPC endpoints.
3. Central evidence foundation: CloudTrail evidence, ALB access-log storage,
   KMS, and CloudWatch log groups.
4. Immutable runtime AMI: Image Builder launches a temporary public builder in
   an edge subnet, installs and validates Docker Compose, AWS CLI, auditd, and
   CloudWatch Agent on the pinned ECS AL2023 parent AMI, then terminates it.
5. Workload substrate: public ALB and private Web, WAS, RDS, and canary S3.
6. Workload observation attachments: ALB logging, VPC Flow Logs, RDS exports,
   host logs, and application log destinations.
7. Application and synthetic seed deployment.
8. Benign D1 runtime evidence validation.
9. Attack fixtures remain disabled until D1 passes.

Terraform file order does not impose dependency order. Operators must advance
the reviewed `network -> evidence -> image -> substrate -> attachments` phase
sequence; output references retain resource-level dependencies without making
an attachment-only observability update invalidate unrelated workload values.
For every phase after `network`, the root reads the current BASE remote-state
`deployment_phase` output and accepts only the immediately preceding phase or
a re-plan of the same phase. A fresh state therefore cannot jump directly to a
higher phase. Explicitly authorized teardown bypasses only this forward-phase
check and remains governed by the separate teardown contracts below.

## Structural validation only

Run from the repository root:

```powershell
terraform fmt -check -recursive infra
terraform -chdir=infra/base init -backend=false
terraform -chdir=infra/base validate
terraform -chdir=infra/base test -no-color
terraform -chdir=infra/hardened init -backend=false
terraform -chdir=infra/hardened validate
python scripts/validate_iac_static.py
python -m unittest discover -s tests -p 'test_*contract.py'
python runner/run_d1_gate.py --manifest fixtures/d1-benign-manifest.json --plan-only
```

These checks prove source structure and contract behavior only. They do not
prove AWS deployment, log delivery, ALB/RDS health, D1 runtime evidence, or
attack-stage behavior. No `terraform apply` belongs in this phase.

The supplied fixture is a plan-contract fixture. It must never be recorded as
D1 completion. After deployment and benign collection, the completion command
must use an independently exported runtime manifest and raw-evidence root:

```powershell
python runner/run_d1_gate.py --manifest evidence/ARGUS-RUN/d1-runtime-manifest.json --require-runtime --evidence-root evidence/ARGUS-RUN/raw
```

The Terraform test uses a mock AWS provider and documentation-only values. It
plans every BASE phase without contacting AWS and must never be reused as an
approved deployment variable file.

## Phase workflow

Copy `base/terraform.tfvars.example` to the ignored `base/terraform.tfvars`,
freeze the required values, and advance only one phase at a time. Review a
saved plan before any separately authorized apply:

```powershell
$env:AWS_PROFILE = "PowerCodex"
terraform -chdir=infra/base plan -input=false -var-file=terraform.tfvars -out=base.tfplan
terraform -chdir=infra/base show -no-color base.tfplan
```

The BASE input boundary is fixed to AWS account `962419263587`,
`ap-northeast-2`, `ap-northeast-2a` and `ap-northeast-2c`, hostname
`argus-base.ar0nica.xyz`, and canary bucket
`argus-base-canary-ap-northeast-2-962419263587`. The `image` phase accepts a
reviewed, pinned ECS-optimized AL2023 parent AMI ID and creates the immutable
runtime AMI used automatically by both private workload hosts. Its temporary
builder is the only public compute, has no SSH/key pair or ingress, and is
terminated by Image Builder; no runtime host receives a public IP or NAT path.
The public ALB accepts one
execution-time public IPv4 `/32`, which the plan/apply scripts resolve without
writing it into the local variable file. No NAT gateway, public Web/WAS IP,
SSH rule, or `argusaws` naming path is present.

BASE creates a new regional ACM certificate, DNS validation records in the
public `ar0nica.xyz` zone, and an A ALB alias record for the hostname. At the
`evidence` phase it creates immutable `argus-base-gateway`, `argus-base-web`,
`argus-base-was`, and `argus-base-seed` ECR repositories, so reviewed digests
can exist before the `substrate` phase. The ignored variable file contains the
pinned ECS AL2023 parent AMI ID for the Image Builder phase and the four
workload/seed image digests. Web runs the gateway and Web compose pair; WAS runs
its own compose service with only a dedicated D1 reader secret. The normal WAS
role never reads the RDS master secret. The fixed seed image contains its own
pinned database client dependencies; the seed path requires only a separate
reviewed temporary permission and its removal before the D1 health gate.

`infra/seed/` is the dedicated digest-pinned seed image source. Its fixed
entrypoint creates only the D1 synthetic table/rows and reader grant,
generates the reader password internally, writes it only to the exact reader
secret, and never emits a password. `Invoke-BaseSyntheticSeed.ps1` runs that
image through SSM with only approved ARNs and endpoints in its command text.
The temporary seed IAM gate grants the WAS role master-secret read and reader
secret write only during this one action; normal runtime retains reader-secret
read only. WAS is installed but not started until the seed has created a
reader-secret version. Both host bootstraps fail closed if Docker Compose, AWS
CLI, auditd, or CloudWatch Agent are absent from the approved no-NAT AMI.

After the `substrate` phase, upload only the approved synthetic canary object,
record its immutable version ID, and place that ID in the ignored variable
file before planning `attachments`. Use `infra/scripts/Invoke-BasePlan.ps1`
for saved plans. `Invoke-BaseApply.ps1` asks for the USD 25 budget email
locally immediately before apply and never persists it. The bootstrap script
and apply script require explicit opt-in switches.

## Controlled teardown

Normal configuration keeps `teardown_authorized = false` and
`teardown_mode = "protected"`. A separately authorized teardown first needs a
reviewed plan that sets `teardown_authorized = true` and chooses exactly one:

- `final_snapshot` with a unique, reviewed per-run snapshot identifier.
- `skip_final_snapshot` only for the approved synthetic-data disposal path.

This transition removes ALB and RDS deletion protection before a later reviewed
destroy. Evidence, ALB-log, canary, and state buckets keep `force_destroy =
false`; retained object versions/delete markers require their own explicit
cross-reviewed disposition. ECR repositories also keep `force_delete = false`.
The dedicated D1 reader secret uses `recovery_window_in_days = 0` because this
is an approved synthetic ephemeral environment; its Terraform deletion is
immediate rather than leaving a scheduled secret residue. The evidence KMS key
has AWS's 30-day deletion window, so it remains a documented pending-deletion
residue after teardown rather than a runtime resource.

## Evidence disposition

The final evidence disposition is a separate post-cross-review action. Keep
the default `evidence_cleanup_authorized = false`; set it only alongside an
authorized teardown and a recorded cross-review reference. Then use
`infra/scripts/Invoke-BaseEvidenceCleanup.ps1` with the exact code-derived
bucket names, cross-review reference, and explicit `-Execute`. That script
removes objects only; it does not change Terraform's `force_destroy = false`
default. A subsequent destroy still requires its own reviewed teardown plan.

Before a final destroy, use the guarded scripts in this order after the
required state export and cross-review: `Invoke-BaseEvidenceCleanup.ps1` for
the exact evidence, ALB-log, and canary buckets including all object versions
and delete markers; `Invoke-BaseEcrCleanup.ps1` for the four exact BASE ECR
repositories; and `Invoke-BaseImageBuilderCleanup.ps1` for the exact Image
Builder output AMI and captured snapshots. After BASE state is exported and
destroy is confirmed, `Invoke-BaseBackendCleanup.ps1` removes every backend
object version/delete marker from the one exact state bucket. These scripts do
not run without both a cross-review reference and `-Execute`.

`Publish-BaseImages.ps1` builds/pushes the fixed gateway, Web, WAS, and seed
contexts as `linux/amd64` to the exact immutable BASE ECR repositories and
prints only digest references. `Publish-BaseCanary.ps1` uploads only
`fixtures/d1-canary.json` to the fixed canary key and prints SHA-256 plus the
immutable VersionId. Neither script persists credentials or deployment inputs.
