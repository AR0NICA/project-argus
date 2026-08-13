# ARGUS application boundary

`services/` retains the D0A-LOCAL S02-S04 contracts. D1 adds one separate,
benign-only runtime path: `GET /d1/observe`, with a `BASE` run ID and the exact
fixture `BEN-D1-OBS-001`. It rejects other fixtures and does not evaluate WAF
or HybridNB; both statuses are explicitly `disabled_not_evaluated`.

The D1 web runtime obtains only the configured exact-version S3 canary object
and the configured SSM sentinel parameter through the standard AWS SDK
credential chain. It does not return or log their contents. The WAS runtime
executes one fixed, parameterized synthetic SELECT, limits the result to ten
rows, carries a nonsecret `argus_d1_query_id` SQL comment, emits structured
stdout logs, and writes only `/var/lib/argus/d1/audit/argus-d1-observe.marker`.
Configure auditd to watch that fixed host-mounted path.

For collector compatibility, configure the CloudWatch Agent to tail these
host-mounted JSONL paths as separate source groups: `D1_APP_LOG_DIR/d0_envelope.jsonl`
to `d0_envelope`, `D1_APP_LOG_DIR/web.jsonl` to `web`, and
`D1_APP_LOG_DIR/was.jsonl` to `was`. Gateway access records are written to
`D1_EVIDENCE_DIR/waf-request-tap.jsonl` and ModSecurity audit records to
`D1_EVIDENCE_DIR/modsecurity-audit.log`; both are source-native gateway files.
The application also mirrors structured records to container stdout for
operator diagnostics, but the collector must use the source-specific files.

`compose.d1.base.yml` accepts only private-ECR image references supplied as
digests. Copy `d1-runtime.env.example` to a protected local environment file,
fill the reviewed runtime inputs (including the locally supplied database
password file), and place the compose file and systemd unit on the approved private
runtime host. Record the resulting reviewed image digests and revision using
`d1-runtime-provenance.json.template`. These assets are packaging contracts;
they do not deploy, pull, call AWS, or prove runtime evidence by themselves.

Apply `sql/d1-synthetic-schema.sql` only through the approved database change
process. It contains three benign synthetic rows and grants a dedicated reader
only SELECT access.
