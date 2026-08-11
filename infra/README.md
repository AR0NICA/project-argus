# ARGUS infrastructure skeleton

This tree is the G1 implementation skeleton. It does not contain an approved
deployment configuration and must not be applied with placeholder values.

## State boundary

- `base/` uses the `argus/base/terraform.tfstate` backend key and
  `argus-base` resource prefix.
- `hardened/` uses the `argus/hardened/terraform.tfstate` backend key and
  `argus-hardened` resource prefix.
- HARDENED is never an in-place mutation of BASE.
- Per-control `argus/control/<control-id>` roots are deferred to D6.

## Frozen deployment order

1. State and safety guards.
2. VPC, subnets, security groups, and VPC endpoints.
3. Central evidence foundation: CloudTrail evidence, ALB access-log storage,
   KMS, and CloudWatch log groups.
4. Workload substrate: public ALB and private Web, WAS, RDS, and canary S3.
5. Workload observation attachments: ALB logging, VPC Flow Logs, RDS exports,
   host logs, and application log destinations.
6. Application and synthetic seed deployment.
7. Benign D1 runtime evidence validation.
8. Attack fixtures remain disabled until D1 passes.

Terraform file order does not impose dependency order. Root modules use output
references and explicit `depends_on` edges where a workload must wait for the
evidence foundation.

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

After the `substrate` phase, upload only the approved synthetic canary object,
record its immutable version ID, and place that ID in the ignored variable
file before planning `attachments`. The application and D1 runtime collection
are separate later work units. This repository intentionally provides no apply
wrapper and no attack-fixture release command.

## Controlled teardown

Normal configuration keeps `teardown_authorized = false` and
`teardown_mode = "protected"`. A separately authorized teardown first needs a
reviewed plan that sets `teardown_authorized = true` and chooses exactly one:

- `final_snapshot` with a unique, reviewed per-run snapshot identifier.
- `skip_final_snapshot` only for the approved synthetic-data disposal path.

This transition removes ALB and RDS deletion protection before a later reviewed
destroy. Evidence and ALB-log buckets keep `force_destroy = false`; retained
objects therefore still require an explicit evidence-disposition decision.
