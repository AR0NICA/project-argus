# D2-SAFETY — kill-switch runtime verification result

Status: **PASS (6/6, composite)** · Date: 2026-08-24 · Environment: BASE · Goal: safety controls
Gate references: D1 `CRR-D1-BASE-R06-2026-08-20`; D2 `CRR-D2-BASE-R2-R3-2026-08-24`.

This is a sanitized summary. Raw evidence (resource ids, endpoints, CIDRs, ARNs,
SSM command ids) is retained only in the local, git-ignored evidence root
`evidence/ARGUS-20260820-BASE-D2/` and
`evidence/ARGUS-20260824-BASE-D2-R3/`. Teardown evidence is retained under
`evidence/ARGUS-20260824-BASE-TEARDOWN-R01/`; none of these raw artifacts are
copied to GitHub or Notion.

The final result is composite: R2 supplies the accepted results for KS1, KS2,
KS3, KS5, and KS6. Its KS4 result is superseded because it used an
administrative actor and denied only `s3:GetObject`, while the deployed Web
workload requests a fixed `VersionId` and therefore requires
`s3:GetObjectVersion`. R3 reran only KS4 against that actual path.

## What D2 proves

Each of the six kill switches was exercised on the live BASE stack as an atomic
**baseline → activate (confirm the path is cut) → recover (confirm restored)**
sequence, and the independent evidence plane was confirmed to keep recording
throughout — without depending on the vulnerable application session or the EC2
test role.

## Kill switches (workbook §7)

| # | Kill switch | Realized as | Activate result | Recover result |
|---|---|---|---|---|
| KS1 | Remove approved CIDR from the ALB security group | revoke/authorize the HTTPS ingress rule | client HTTPS times out (blocked) | HTTPS reachable again |
| KS2 | Edge/WAF block-all | halt the ModSecurity gateway container (nginx config is baked/read-only, so a container-level block is the reversible equivalent of a block-all rule) | edge refuses all requests | edge serves normally |
| KS3 | Detach the web test role | disassociate/associate the web instance profile | no instance profile associated | role re-associated |
| KS4 | Block the exact versioned canary workload path | add/remove an explicit `s3:GetObjectVersion` Deny for the fixed key and VersionId | `/d1/observe` 200 → 503 and Web-role call → explicit AccessDenied | `/d1/observe` 200 and Web-role call succeeds |
| KS5 | Remove WAS TCP 8090 rule | revoke/authorize the admin-API ingress rule | rule absent | rule restored |
| KS6 | Stop the vulnerable app | `systemctl stop/start` the WAS service (no `ARGUS_LAB_MODE` flag exists, so the switch is realized as stopping the vulnerable app) | service inactive, health unreachable | service active, health 200 |

## Independent evidence-collection persists (D2 core invariant)

For R2, CloudTrail recorded every accepted kill-switch action within the test window: the two
security-group revoke/authorize pairs (KS1, KS5), the bucket-policy changes
(the superseded KS4 attempt), the instance-profile disassociate/associate pair
(KS3), and the SSM commands (KS2, KS6). Crucially, **KS3 detached the web test role and CloudTrail
still recorded the action** — demonstrating that the central evidence path does
not depend on the vulnerable application session or the EC2 test role, exactly as
the safety contract requires.

For R3 KS4, CloudTrail recorded six unique scoped S3 `GetObject` data events for
the exact VersionId: four successes and two `AccessDenied` events, all from the
Web test role. It also recorded both `PutBucketPolicy` actions. This correlates
the real application and same-role CLI probes across baseline, deny, and
recovery without relying on the administrative CLI as the workload proof.

## Post-test and teardown state

All six switches are accepted as recovered to baseline across R2 and R3. After
R3, the original canary policy was restored exactly, the workload returned to
healthy, RDS was available, and `terraform plan` reported no changes.

After cross-review and explicit teardown approval, a local pre-teardown state
export was retained, the versioned evidence/access-log/canary objects, ECR
images, and the exact Image Builder AMI/snapshot were removed, and a saved
destroy plan was applied. The plan contained 142 deletes with zero creates,
updates, or replacements; apply completed with 142 resources destroyed.
Post-destroy checks found an empty Terraform state and no active BASE EC2, ALB,
RDS, VPC, CloudTrail, workload buckets, or ECR repositories. The BASE backend
bucket remains, but its state and lock object versions/delete markers are empty.
The evidence KMS key remains only in AWS `PendingDeletion` state until its
scheduled deletion date; this is an expected service-managed residual, not a
live usable BASE stack.
