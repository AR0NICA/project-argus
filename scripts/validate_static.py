"""No-Docker structural checks for the D0A local lab."""
import ast
import json
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
print("static validation passed: JSON, Python syntax, topology, limits, and DB boundary")
