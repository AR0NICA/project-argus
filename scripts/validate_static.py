"""No-Docker structural checks for the D0A local lab and the D3 unit contract."""
import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

for file in [ROOT / "services/web/app.py", ROOT / "services/was/app.py"]:
    ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
for file in (ROOT / "schemas").glob("*.json"):
    json.loads(file.read_text(encoding="utf-8"))
json.loads((ROOT / "fixtures/d0a-local-fixtures.json").read_text(encoding="utf-8"))

compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
required = ["127.0.0.1:18080:8080", "networks: [ingress, edge]", "networks: [edge, app]", "networks: [app, data]", "networks: [data]", "ingress:", "com.docker.network.bridge.host_binding_ipv4: \"127.0.0.1\"", "mysql:8.4@sha256:8dbcf531a03aade657e181b9cf2f1d1803ce621a1d55610cb44cb531ab7d7db6"]
missing = [item for item in required if item not in compose]
if missing:
    raise SystemExit("compose contract missing: " + ", ".join(missing))

aws_web_bootstrap = (ROOT / "infra/modules/compute/templates/web-user-data.sh.tftpl").read_text(encoding="utf-8")
aws_web_required = ["networks: [ingress, edge]", "networks: [edge, aws_egress]", "  ingress:\n", "  edge:\n    internal: true"]
aws_web_missing = [item for item in aws_web_required if item not in aws_web_bootstrap]
if aws_web_missing:
    raise SystemExit("AWS Web bootstrap network contract missing: " + ", ".join(aws_web_missing))

aws_was_bootstrap = (ROOT / "infra/modules/compute/templates/was-user-data.sh.tftpl").read_text(encoding="utf-8")
aws_was_required = ["name_format = USER", "printf 'name = %s\\n'", "service auditd restart", "systemctl disable --now ecs.service || true"]
aws_was_missing = [item for item in aws_was_required if item not in aws_was_bootstrap]
if aws_was_missing:
    raise SystemExit("AWS WAS audit identity contract missing: " + ", ".join(aws_was_missing))

base_iac = (ROOT / "infra/base/main.tf").read_text(encoding="utf-8")
if 'was_private_ip        = "10.20.20.81"' not in base_iac:
    raise SystemExit("BASE WAS fixed private IP contract missing")

fixture = json.loads((ROOT / "fixtures/d0a-local-fixtures.json").read_text())
if fixture["synthetic_row_count"] > 10:
    raise SystemExit("synthetic row limit exceeded")
web_docker = (ROOT / "services/web/Dockerfile").read_text()
was_docker = (ROOT / "services/was/Dockerfile").read_text()
if "mysql-connector" in web_docker or "mysql-connector" not in was_docker or "MYSQL_USER" in compose:
    raise SystemExit("database dependency boundary is wrong")
for dockerfile in [ROOT / "services/gateway/Dockerfile", ROOT / "services/web/Dockerfile", ROOT / "services/was/Dockerfile"]:
    if "@sha256:" not in dockerfile.read_text(encoding="utf-8").splitlines()[0]:
        raise SystemExit("base image is not digest pinned: " + str(dockerfile))
if "debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818" not in (ROOT / "services/gateway/Dockerfile").read_text(encoding="utf-8"):
    raise SystemExit("gateway Debian digest is not the approved pin")
gateway = (ROOT / "services/gateway/nginx.conf").read_text(encoding="utf-8")
for setting in ["error_log /dev/stderr", "pid /var/run/nginx.pid", "client_body_temp_path /var/cache/nginx/client_temp", "proxy_temp_path /var/cache/nginx/proxy_temp", "fastcgi_temp_path /var/cache/nginx/fastcgi_temp", "uwsgi_temp_path /var/cache/nginx/uwsgi_temp", "scgi_temp_path /var/cache/nginx/scgi_temp", "proxy_max_temp_file_size 0", "client_body_buffer_size 32k", "proxy_buffer_size 32k", "proxy_buffers 4 32k", "proxy_busy_buffers_size 64k"]:
    if setting not in gateway:
        raise SystemExit("read-only gateway setting missing: " + setting)
modsecurity = (ROOT / "services/gateway/modsecurity.conf").read_text(encoding="utf-8")
if "Include /etc/modsecurity/crs/crs-setup.conf" not in modsecurity or "Include /usr/share/modsecurity-crs/rules/*.conf" not in modsecurity:
    raise SystemExit("CRS package-path contract missing")
runner = (ROOT / "scripts/run-d0a.ps1").read_text(encoding="utf-8")
for setting in ["while ((Get-Date) -lt $deadline)", "-ErrorAction Stop", "gateway-health-last-error.txt", "failure.json", "compose-ps.txt", "compose-logs.txt", "docker compose port gateway 8080", "gateway-published-port.txt", "127\\.0\\.0\\.1:18080"]:
    if setting not in runner:
        raise SystemExit("runner readiness/diagnostic setting missing: " + setting)
# D3-UNIT-STAGES contract: the fixtures file must mirror the frozen core authority.
for file in [ROOT / "runner/d3_core.py", ROOT / "runner/run_d3_unit.py", ROOT / "runner/collect_d3_runtime.py", ROOT / "runner/run_d3_gate.py", ROOT / "scripts/validate_d3_evidence.py", ROOT / "tests/test_d3_contract.py"]:
    ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
sys.path.insert(0, str(ROOT / "runner"))
import d3_core  # noqa: E402
d3 = json.loads((ROOT / "fixtures/d3-unit-fixtures.json").read_text(encoding="utf-8"))
if len(d3["stages"]) != len(d3_core.STAGES):
    raise SystemExit("D3 fixture stage count does not match the core authority")
if d3["safety_bounds"]["max_result_rows"] > 10 or d3["safety_bounds"]["max_result_bytes"] > 32768:
    raise SystemExit("D3 fixture violates the 10-row / 32 KiB guard")
if d3["safety_bounds"]["s01_max_total_requests"] > 12 or d3["safety_bounds"]["max_rps"] > 1 or d3["safety_bounds"]["concurrency"] != 1:
    raise SystemExit("D3 fixture violates the recon budget or rate/concurrency limits")
if tuple(d3["allow_list_actions"]) != d3_core.ALLOWED_ACTIONS:
    raise SystemExit("D3 fixture action allow-list drifted from the core authority")
if d3_core.MAX_ROWS > 10 or d3_core.MAX_BYTES > 32768:
    raise SystemExit("D3 core guard constants drifted")
for fixture_stage, core_stage in zip(d3["stages"], d3_core.STAGES):
    if (fixture_stage["stage"], fixture_stage["fixture_or_resource_id"], fixture_stage["action"], fixture_stage["success_token"], fixture_stage["handoff_in"], fixture_stage["handoff_out"]) != (core_stage["stage"], core_stage["fixture"], core_stage["action"], core_stage["success_field"], core_stage["handoff_in"], core_stage["handoff_out"]):
        raise SystemExit("D3 fixture stage contract drifted from the core authority: " + fixture_stage["stage"])

print("static validation passed: JSON, Python syntax, topology, limits, DB boundary, and D3 unit contract")
