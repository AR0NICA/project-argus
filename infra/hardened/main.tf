locals {
  environment = "HARDENED"
  name_prefix = "argus-hardened"
  tags = {
    Project     = "ARGUS"
    Environment = local.environment
    ManagedBy   = "IaC"
    Owner       = var.owner
    Runbook     = "AWS-3Tier-HARDENED"
  }
  phase_rank = {
    disabled    = 0
    network     = 1
    evidence    = 2
    substrate   = 3
    attachments = 4
  }
  network_enabled     = local.phase_rank[var.deployment_phase] >= 1
  evidence_enabled    = local.phase_rank[var.deployment_phase] >= 2
  substrate_enabled   = local.phase_rank[var.deployment_phase] >= 3
  attachments_enabled = local.phase_rank[var.deployment_phase] >= 4
}

resource "terraform_data" "d0_guard" {
  input = {
    environment         = local.environment
    phase               = var.deployment_phase
    teardown_authorized = var.teardown_authorized
    teardown_mode       = var.teardown_mode
  }

  lifecycle {
    precondition {
      condition     = !local.network_enabled || (length(var.allowed_account_ids) == 1 && length(var.availability_zones) == 2 && length(var.allowed_test_cidrs) > 0)
      error_message = "network phase requires one account ID, two AZs, and at least one approved test CIDR."
    }
    precondition {
      condition     = !local.evidence_enabled || (var.evidence_bucket_name != "" && var.alb_access_log_bucket_name != "")
      error_message = "evidence phase requires frozen evidence and ALB access-log bucket names."
    }
    precondition {
      condition     = !local.substrate_enabled || (var.tls_certificate_arn != "" && var.web_ami_id != "" && var.was_ami_id != "" && var.canary_bucket_name != "" && (!var.enable_budget || var.budget_alert_email != ""))
      error_message = "substrate phase requires certificate, AMIs, canary bucket name, and budget email when budget is enabled."
    }
    precondition {
      condition     = !local.attachments_enabled || var.canary_object_version_id != ""
      error_message = "attachments phase requires the approved synthetic canary object version ID."
    }
    precondition {
      condition     = var.teardown_authorized || (var.teardown_mode == "protected" && var.teardown_final_snapshot_identifier == "")
      error_message = "teardown settings require explicit teardown_authorized=true."
    }
    precondition {
      condition     = !var.teardown_authorized || contains(["final_snapshot", "skip_final_snapshot"], var.teardown_mode)
      error_message = "authorized teardown must choose final_snapshot or skip_final_snapshot."
    }
    precondition {
      condition     = !var.teardown_authorized || var.teardown_mode != "final_snapshot" || var.teardown_final_snapshot_identifier != ""
      error_message = "final_snapshot teardown requires a unique reviewed snapshot identifier."
    }
  }
}

module "safety" {
  source = "../modules/safety"

  environment        = local.environment
  name_prefix        = local.name_prefix
  enable_budget      = local.network_enabled && var.enable_budget
  monthly_limit_usd  = var.monthly_limit_usd
  budget_alert_email = var.budget_alert_email
}

module "network" {
  count  = local.network_enabled ? 1 : 0
  source = "../modules/network"

  name_prefix        = local.name_prefix
  vpc_cidr           = "10.20.0.0/16"
  availability_zones = var.availability_zones
  allowed_test_cidrs = var.allowed_test_cidrs
  web_port           = 8080
  was_business_port  = 8081
  was_admin_port     = 8090
  db_port            = 3306
  tags               = local.tags
  subnet_cidrs = {
    edge_a = "10.20.0.0/24"
    edge_b = "10.20.1.0/24"
    web_a  = "10.20.10.0/24"
    web_b  = "10.20.11.0/24"
    was_a  = "10.20.20.0/24"
    was_b  = "10.20.21.0/24"
    data_a = "10.20.30.0/24"
    data_b = "10.20.31.0/24"
  }

  depends_on = [terraform_data.d0_guard, module.safety]
}

module "observability" {
  count  = local.evidence_enabled ? 1 : 0
  source = "../modules/observability"

  project                         = "ARGUS"
  environment                     = local.environment
  name_prefix                     = local.name_prefix
  aws_account_id                  = var.allowed_account_ids[0]
  vpc_id                          = module.network[0].vpc_id
  evidence_bucket_name            = var.evidence_bucket_name
  alb_access_log_bucket_name      = var.alb_access_log_bucket_name
  retention_in_days               = var.evidence_retention_in_days
  enable_s3_getobject_data_events = local.attachments_enabled
  enable_vpc_flow_logs            = true
  s3_getobject_resource_arn       = local.attachments_enabled ? "arn:aws:s3:::${var.canary_bucket_name}/${var.canary_object_key}" : ""
  tags                            = local.tags

  depends_on = [module.network]
}

module "edge" {
  count  = local.substrate_enabled ? 1 : 0
  source = "../modules/edge"

  name_prefix                = local.name_prefix
  vpc_id                     = module.network[0].vpc_id
  edge_subnet_ids            = module.network[0].edge_subnet_ids
  alb_security_group_id      = module.network[0].security_group_ids.alb
  certificate_arn            = var.tls_certificate_arn
  web_port                   = 8080
  health_check_path          = "/health"
  enable_deletion_protection = !var.teardown_authorized
  access_log_bucket_name     = module.observability[0].alb_access_log_bucket_name
  access_log_prefix          = module.observability[0].alb_access_log_prefix
  tags                       = local.tags

  depends_on = [module.observability]
}

module "compute" {
  count  = local.substrate_enabled ? 1 : 0
  source = "../modules/compute"

  name_prefix           = local.name_prefix
  web_ami_id            = var.web_ami_id
  was_ami_id            = var.was_ami_id
  web_instance_type     = var.web_instance_type
  was_instance_type     = var.was_instance_type
  web_subnet_id         = module.network[0].web_subnet_ids[0]
  was_subnet_id         = module.network[0].was_subnet_ids[0]
  web_security_group_id = module.network[0].security_group_ids.web
  was_security_group_id = module.network[0].security_group_ids.was
  web_target_group_arn  = module.edge[0].web_target_group_arn
  web_port              = 8080
  web_log_group_arns = [
    module.observability[0].source_log_group_arns["nginx_modsecurity"],
    module.observability[0].source_log_group_arns["d0_envelope"],
    module.observability[0].source_log_group_arns["web"],
    module.observability[0].source_log_group_arns["host"],
  ]
  was_log_group_arns = [
    module.observability[0].source_log_group_arns["was"],
    module.observability[0].source_log_group_arns["host"],
  ]
  tags = local.tags

  depends_on = [module.observability]
}

module "data" {
  count  = local.substrate_enabled ? 1 : 0
  source = "../modules/data"

  name_prefix                  = local.name_prefix
  data_subnet_ids              = module.network[0].data_subnet_ids
  rds_security_group_id        = module.network[0].security_group_ids.rds
  instance_class               = var.rds_instance_class
  allocated_storage            = var.rds_allocated_storage
  backup_retention_days        = 1
  deletion_protection          = !var.teardown_authorized
  skip_final_snapshot          = var.teardown_authorized && var.teardown_mode == "skip_final_snapshot"
  final_snapshot_identifier    = var.teardown_authorized && var.teardown_mode == "final_snapshot" ? var.teardown_final_snapshot_identifier : ""
  native_log_retention_in_days = var.evidence_retention_in_days
  tags                         = local.tags

  depends_on = [module.observability]
}

module "canary" {
  count  = local.substrate_enabled ? 1 : 0
  source = "../modules/canary"

  name_prefix                 = local.name_prefix
  bucket_name                 = var.canary_bucket_name
  object_key                  = var.canary_object_key
  object_version_id           = local.attachments_enabled ? var.canary_object_version_id : ""
  web_role_name               = local.attachments_enabled ? module.compute[0].web_test_role_name : ""
  attach_exact_version_policy = local.attachments_enabled
  tags                        = local.tags

  depends_on = [module.observability, module.edge, module.compute, module.data]
}

resource "terraform_data" "observation_source_attachments" {
  count = local.attachments_enabled ? 1 : 0
  input = {
    canary_version_id = var.canary_object_version_id
    canary_object_arn = "arn:aws:s3:::${var.canary_bucket_name}/${var.canary_object_key}"
  }

  depends_on = [module.observability, module.edge, module.compute, module.data, module.canary]
}
