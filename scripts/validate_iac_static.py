"""Closed-world static checks for the ARGUS G1 IaC skeleton."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infra"


def read(relative):
    path = ROOT / relative
    if not path.is_file():
        raise AssertionError(f"missing required file: {relative}")
    return path.read_text(encoding="ascii")


def require(text, needle, label):
    if needle not in text:
        raise AssertionError(f"missing {label}: {needle}")


def variable_names(text):
    return set(re.findall(r'variable\s+"([^"]+)"', text))


def main():
    base_main = read("infra/base/main.tf")
    hardened_main = read("infra/hardened/main.tf")
    base_vars = read("infra/base/variables.tf")
    hardened_vars = read("infra/hardened/variables.tf")
    base_tfvars = read("infra/base/terraform.tfvars.example")
    hardened_tfvars = read("infra/hardened/terraform.tfvars.example")
    network = read("infra/modules/network/main.tf")
    observability = read("infra/modules/observability/main.tf")
    data = read("infra/modules/data/main.tf")
    d1_validator = read("observability/validate_d1_manifest.py")
    d1_fixture = read("fixtures/d1-benign-manifest.json")

    require(read("infra/base/backend.hcl.example"), 'key            = "argus/base/terraform.tfstate"', "BASE backend key")
    require(read("infra/hardened/backend.hcl.example"), '"argus/hardened/terraform.tfstate"', "HARDENED backend key")
    require(base_main, 'name_prefix        = "argus-base"', "BASE name prefix")
    require(hardened_main, 'name_prefix = "argus-hardened"', "HARDENED name prefix")
    common_experiment_inputs = {
        "allowed_test_cidrs",
        "aws_region",
        "budget_alert_email",
        "canary_bucket_name",
        "canary_object_key",
        "canary_object_version_id",
        "deployment_phase",
        "enable_budget",
        "evidence_retention_in_days",
        "monthly_limit_usd",
        "owner",
        "rds_allocated_storage",
        "rds_instance_class",
        "teardown_authorized",
        "teardown_final_snapshot_identifier",
        "teardown_mode",
        "was_instance_type",
        "web_instance_type",
    }
    if not common_experiment_inputs <= variable_names(base_vars) or not common_experiment_inputs <= variable_names(hardened_vars):
        raise AssertionError("BASE and HARDENED common experiment inputs differ")
    for variable_name in ("evidence_bucket_name", "alb_access_log_bucket_name"):
        if variable_name in variable_names(base_vars) or variable_name in variable_names(hardened_vars):
            raise AssertionError(f"frozen bucket name remains a root input: {variable_name}")
        if variable_name in base_tfvars or variable_name in hardened_tfvars:
            raise AssertionError(f"frozen bucket name remains in a tfvars example: {variable_name}")
    require(
        base_main,
        'evidence_bucket_name       = "${local.name_prefix}-d1-evidence-${var.aws_region}-${local.bucket_account_id}"',
        "frozen BASE evidence bucket formula",
    )
    require(
        base_main,
        'alb_access_log_bucket_name = "${local.name_prefix}-alb-access-${var.aws_region}-${local.bucket_account_id}"',
        "frozen BASE ALB bucket formula",
    )
    require(
        hardened_main,
        'evidence_bucket_name       = "${local.name_prefix}-d1-evidence-${var.aws_region}-${local.bucket_account_id}"',
        "frozen HARDENED evidence bucket formula",
    )
    require(
        hardened_main,
        'alb_access_log_bucket_name = "${local.name_prefix}-alb-access-${var.aws_region}-${local.bucket_account_id}"',
        "frozen HARDENED ALB bucket formula",
    )

    for cidr in (
        "10.20.0.0/16",
        "10.20.0.0/24",
        "10.20.1.0/24",
        "10.20.10.0/24",
        "10.20.11.0/24",
        "10.20.20.0/24",
        "10.20.21.0/24",
        "10.20.30.0/24",
        "10.20.31.0/24",
    ):
        require(base_main, cidr, "frozen BASE CIDR")
    for forbidden in ('resource "aws_nat_gateway"', "from_port = 22", "from_port = 3389"):
        if forbidden in network:
            raise AssertionError(f"forbidden network contract: {forbidden}")
    if re.search(r"\b(?:ingress|egress)\s*=\s*\[\]", network):
        raise AssertionError("security-group bodies must not conflict with standalone rule resources")
    require(network, 'for_each = toset(["ssm", "ssmmessages", "ec2messages", "logs", "ecr.api", "ecr.dkr", "secretsmanager"])', "approved interface endpoints")
    compute = read("infra/modules/compute/main.tf")
    if compute.count("http_put_response_hop_limit = 2") != 2:
        raise AssertionError("both private Docker hosts must receive IMDSv2 responses")
    was_bootstrap = read("infra/modules/compute/templates/was-user-data.sh.tftpl")
    require(was_bootstrap, "service auditd restart", "supported auditd reload")
    require(network, 'service_name      = "com.amazonaws.${var.aws_region}.s3"', "S3 gateway endpoint")
    require(network, 'cidr_ipv4         = "10.20.0.2/32"', "Image Builder VPC resolver egress")
    image_builder = read("infra/modules/image_builder/main.tf")
    require(image_builder, "docker-compose-linux-x86_64", "fixed Docker Compose asset")
    require(image_builder, "33b208d7e76639db742fae84b966cc01dacae58ca3fc4dabbc907045aefdf0c4", "Docker Compose asset digest")
    require(image_builder, "audit-3.1.5-1.amzn2023.0.2", "fixed audit package")
    require(image_builder, "amazon-cloudwatch-agent-1.300069.1-1.amzn2023", "fixed CloudWatch Agent package")
    was_user_data = read("infra/modules/compute/templates/was-user-data.sh.tftpl")
    require(was_user_data, "never,task\\|task,never", "audit syscall suppression removal")
    require(was_user_data, "augenrules --load", "audit watch reload")

    require(observability, 'resource "aws_cloudtrail" "d1"', "CloudTrail foundation")
    require(observability, 'resource "aws_s3_bucket" "evidence"', "CloudTrail evidence bucket")
    require(observability, 'resource "aws_s3_bucket" "alb_access"', "ALB access-log bucket")
    require(observability, 'resource "terraform_data" "bucket_name_contract"', "distinct frozen bucket contract")
    require(observability, 'enable_log_file_validation    = true', "CloudTrail validation")
    require(observability, 'equals = ["GetObject"]', "scoped S3 GetObject selector")
    require(observability, 'traffic_type             = "ALL"', "VPC Flow Logs ALL")
    require(observability, "max_aggregation_interval = 60", "VPC Flow Logs 60-second aggregation")
    require(base_main, 'evidence    = 2', "evidence phase rank")
    require(base_main, 'image       = 3', "image phase after evidence")
    require(base_main, 'substrate   = 4', "substrate phase after image")
    require(base_main, 'count  = local.evidence_enabled ? 1 : 0', "evidence phase gate")
    require(base_main, 'count  = local.substrate_enabled ? 1 : 0', "workload substrate phase gate")
    require(base_main, 'data "terraform_remote_state" "current_base"', "state-backed phase transition gate")
    require(base_main, 'expected_previous_phase', "immediately preceding phase contract")
    require(base_main, 'enable_deletion_protection = !var.teardown_authorized', "controlled ALB teardown")
    require(base_main, 'deletion_protection          = !var.teardown_authorized', "controlled RDS teardown")
    require(data, 'final_snapshot_identifier       = var.skip_final_snapshot ? null', "controlled RDS snapshot")
    require(data, 'engine_version                  = "8.4.10"', "pinned BASE MySQL patch version")
    if '${var.name_prefix}-final' in data:
        raise AssertionError("fixed RDS final snapshot identifier blocks repeat teardown")

    require(d1_fixture, '"schema_version": "argus.d1-evidence-manifest/v2"', "D1 native-correlation schema")
    require(d1_validator, '"start_epoch","end_epoch"', "Flow Log native time anchors")
    require(d1_validator, '"audit_epoch","audit_serial"', "auditd native time anchors")

    terraform_text = "\n".join(path.read_text(encoding="ascii") for path in INFRA.rglob("*.tf"))
    for forbidden in ('associate_public_ip_address = true', 'publicly_accessible         = true'):
        if forbidden in terraform_text:
            raise AssertionError(f"forbidden public workload setting: {forbidden}")
    if "ATK-" in terraform_text or "ATK-" in d1_fixture:
        raise AssertionError("attack fixture leaked into G1/D1 artifacts")

    print("ARGUS G1 IaC static validation passed")


if __name__ == "__main__":
    main()
