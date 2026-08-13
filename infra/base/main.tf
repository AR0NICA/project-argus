locals {
  environment        = "BASE"
  name_prefix        = "argus-base"
  aws_account_id     = "962419263587"
  availability_zones = ["ap-northeast-2a", "ap-northeast-2c"]
  tags = {
    Project     = "ARGUS"
    Environment = local.environment
    ManagedBy   = "IaC"
    Owner       = var.owner
    Runbook     = "AWS-3Tier-BASE"
  }
  phase_rank = {
    disabled    = 0
    network     = 1
    evidence    = 2
    image       = 3
    substrate   = 4
    attachments = 5
  }
  network_enabled     = local.phase_rank[var.deployment_phase] >= 1
  evidence_enabled    = local.phase_rank[var.deployment_phase] >= 2
  image_enabled       = local.phase_rank[var.deployment_phase] >= 3
  substrate_enabled   = local.phase_rank[var.deployment_phase] >= 4
  attachments_enabled = local.phase_rank[var.deployment_phase] >= 5
  bucket_account_id   = local.aws_account_id

  evidence_bucket_name       = "${local.name_prefix}-d1-evidence-${var.aws_region}-${local.bucket_account_id}"
  alb_access_log_bucket_name = "${local.name_prefix}-alb-access-${var.aws_region}-${local.bucket_account_id}"
  artifact_enabled           = local.phase_rank[var.deployment_phase] >= 2
  ecr_repository_names       = toset(["gateway", "web", "was", "seed"])
  expected_previous_phase = {
    evidence    = "network"
    image       = "evidence"
    substrate   = "image"
    attachments = "substrate"
  }
  phase_transition_check_enabled = local.phase_rank[var.deployment_phase] >= 2 && !var.teardown_authorized
}

data "terraform_remote_state" "current_base" {
  count   = local.phase_transition_check_enabled ? 1 : 0
  backend = "s3"
  config = {
    bucket       = "argus-terraform-state-ap-northeast-2-962419263587"
    key          = "argus/base/terraform.tfstate"
    region       = "ap-northeast-2"
    encrypt      = true
    use_lockfile = true
  }
}

data "aws_route53_zone" "base" {
  count        = local.substrate_enabled ? 1 : 0
  name         = "${var.hosted_zone_name}."
  private_zone = false
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
      condition     = !local.network_enabled || (length(var.allowed_test_cidrs) == 1 && endswith(var.allowed_test_cidrs[0], "/32"))
      error_message = "network phase requires the approved account, two AZs, and one execution-time public IPv4 /32."
    }
    precondition {
      condition = !local.evidence_enabled || (
        local.evidence_bucket_name != local.alb_access_log_bucket_name &&
        length(local.evidence_bucket_name) <= 63 &&
        length(local.alb_access_log_bucket_name) <= 63
      )
      error_message = "evidence phase requires distinct code-derived evidence and ALB access-log bucket names."
    }
    precondition {
      condition     = !local.image_enabled || can(regex("^ami-[0-9a-f]{8,17}$", var.builder_parent_ami_id))
      error_message = "image phase requires the approved pinned ECS AL2023 parent AMI ID."
    }
    precondition {
      condition     = !local.substrate_enabled || (can(regex("^sha256:[0-9a-f]{64}$", var.gateway_image_digest)) && can(regex("^sha256:[0-9a-f]{64}$", var.web_image_digest)) && can(regex("^sha256:[0-9a-f]{64}$", var.was_image_digest)) && can(regex("^sha256:[0-9a-f]{64}$", var.seed_image_digest)) && (!var.enable_budget || var.budget_alert_email != ""))
      error_message = "substrate phase requires pinned gateway/Web/WAS/seed digests and a local budget email when budget is enabled."
    }
    precondition {
      condition     = !local.attachments_enabled || var.canary_object_version_id != ""
      error_message = "attachments phase requires the approved synthetic canary object version ID."
    }
    precondition {
      condition = !local.phase_transition_check_enabled || contains(
        [local.expected_previous_phase[var.deployment_phase], var.deployment_phase],
        try(data.terraform_remote_state.current_base[0].outputs.deployment_phase, "")
      )
      error_message = "deployment phase must advance from the immediately preceding phase recorded in the BASE remote state, or re-plan the currently recorded phase."
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
  aws_region         = var.aws_region
  vpc_cidr           = "10.20.0.0/16"
  availability_zones = local.availability_zones
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

  depends_on = [module.safety]
}

resource "aws_vpc_security_group_ingress_rule" "image_builder_to_vpce" {
  count                        = local.network_enabled ? 1 : 0
  security_group_id            = module.network[0].security_group_ids.vpce
  referenced_security_group_id = module.network[0].security_group_ids.image_builder
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Image Builder SSM control traffic"
}

resource "aws_vpc_security_group_egress_rule" "was_to_s3_gateway" {
  count             = local.network_enabled ? 1 : 0
  security_group_id = module.network[0].security_group_ids.was
  prefix_list_id    = module.network[0].s3_prefix_list_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "WAS ECR image layer retrieval through S3 gateway"
}

resource "aws_vpc_security_group_egress_rule" "runtime_dns" {
  for_each = local.network_enabled ? {
    web_tcp = { tier = "web", protocol = "tcp" }
    web_udp = { tier = "web", protocol = "udp" }
    was_tcp = { tier = "was", protocol = "tcp" }
    was_udp = { tier = "was", protocol = "udp" }
  } : {}

  security_group_id = module.network[0].security_group_ids[each.value.tier]
  cidr_ipv4         = "10.20.0.2/32"
  from_port         = 53
  to_port           = 53
  ip_protocol       = each.value.protocol
  description       = "${upper(each.value.tier)} VPC resolver ${upper(each.value.protocol)}"
}

resource "aws_ecr_repository" "workload" {
  for_each             = local.artifact_enabled ? local.ecr_repository_names : toset([])
  name                 = "${local.name_prefix}-${each.value}"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
  tags = merge(local.tags, { Component = "ecr", Workload = each.value, Name = "${local.name_prefix}-${each.value}" })
}

resource "aws_ssm_parameter" "web_bootstrap_sentinel" {
  count = local.substrate_enabled ? 1 : 0
  name  = "/argus/base/d1/sentinel"
  type  = "String"
  value = var.web_sentinel_value
  tags  = merge(local.tags, { Component = "compute", Purpose = "web-bootstrap-sentinel" })
}

resource "aws_acm_certificate" "base" {
  count             = local.substrate_enabled ? 1 : 0
  domain_name       = var.hostname
  validation_method = "DNS"
  lifecycle { create_before_destroy = true }
  tags = merge(local.tags, { Component = "edge", Name = var.hostname })
}

resource "aws_route53_record" "acm_validation" {
  count = local.substrate_enabled ? 1 : 0

  allow_overwrite = true
  name            = tolist(aws_acm_certificate.base[0].domain_validation_options)[0].resource_record_name
  records         = [tolist(aws_acm_certificate.base[0].domain_validation_options)[0].resource_record_value]
  ttl             = 60
  type            = tolist(aws_acm_certificate.base[0].domain_validation_options)[0].resource_record_type
  zone_id         = data.aws_route53_zone.base[0].zone_id
}

resource "aws_acm_certificate_validation" "base" {
  count                   = local.substrate_enabled ? 1 : 0
  certificate_arn         = aws_acm_certificate.base[0].arn
  validation_record_fqdns = [aws_route53_record.acm_validation[0].fqdn]
}

module "observability" {
  count  = local.evidence_enabled ? 1 : 0
  source = "../modules/observability"

  project                         = "ARGUS"
  environment                     = local.environment
  name_prefix                     = local.name_prefix
  aws_account_id                  = local.aws_account_id
  vpc_id                          = module.network[0].vpc_id
  evidence_bucket_name            = local.evidence_bucket_name
  alb_access_log_bucket_name      = local.alb_access_log_bucket_name
  retention_in_days               = var.evidence_retention_in_days
  enable_s3_getobject_data_events = local.attachments_enabled
  enable_vpc_flow_logs            = true
  s3_getobject_resource_arn       = local.attachments_enabled ? "arn:aws:s3:::${var.canary_bucket_name}/${var.canary_object_key}" : ""
  tags                            = local.tags

}

module "image_builder" {
  count  = local.image_enabled ? 1 : 0
  source = "../modules/image_builder"

  name_prefix               = local.name_prefix
  aws_region                = var.aws_region
  parent_ami_id             = var.builder_parent_ami_id
  builder_subnet_id         = module.network[0].edge_subnet_ids[0]
  builder_security_group_id = module.network[0].security_group_ids.image_builder
  component_version         = var.image_builder_component_version
  recipe_version            = var.image_builder_recipe_version
  tags                      = local.tags

  depends_on = [aws_vpc_security_group_ingress_rule.image_builder_to_vpce]
}

module "edge" {
  count  = local.substrate_enabled ? 1 : 0
  source = "../modules/edge"

  name_prefix                = local.name_prefix
  vpc_id                     = module.network[0].vpc_id
  edge_subnet_ids            = module.network[0].edge_subnet_ids
  alb_security_group_id      = module.network[0].security_group_ids.alb
  certificate_arn            = aws_acm_certificate_validation.base[0].certificate_arn
  web_port                   = 8080
  health_check_path          = "/health"
  enable_deletion_protection = !var.teardown_authorized
  access_log_bucket_name     = module.observability[0].alb_access_log_bucket_name
  access_log_prefix          = module.observability[0].alb_access_log_prefix
  tags                       = local.tags

}

resource "aws_route53_record" "alb" {
  count   = local.substrate_enabled ? 1 : 0
  zone_id = data.aws_route53_zone.base[0].zone_id
  name    = var.hostname
  type    = "A"
  alias {
    evaluate_target_health = true
    name                   = module.edge[0].alb_dns_name
    zone_id                = module.edge[0].alb_zone_id
  }
}

module "compute" {
  count  = local.substrate_enabled ? 1 : 0
  source = "../modules/compute"

  name_prefix           = local.name_prefix
  web_ami_id            = module.image_builder[0].ami_id
  was_ami_id            = module.image_builder[0].ami_id
  web_instance_type     = var.web_instance_type
  was_instance_type     = var.was_instance_type
  web_subnet_id         = module.network[0].web_subnet_ids[0]
  was_subnet_id         = module.network[0].was_subnet_ids[0]
  was_private_ip        = "10.20.20.81"
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
  aws_region                       = var.aws_region
  ecr_registry                     = split("/", aws_ecr_repository.workload["web"].repository_url)[0]
  gateway_ecr_repository_arn       = aws_ecr_repository.workload["gateway"].arn
  gateway_ecr_repository_url       = aws_ecr_repository.workload["gateway"].repository_url
  web_ecr_repository_arn           = aws_ecr_repository.workload["web"].arn
  web_ecr_repository_url           = aws_ecr_repository.workload["web"].repository_url
  was_ecr_repository_arn           = aws_ecr_repository.workload["was"].arn
  was_ecr_repository_url           = aws_ecr_repository.workload["was"].repository_url
  seed_ecr_repository_arn          = aws_ecr_repository.workload["seed"].arn
  seed_ecr_repository_url          = aws_ecr_repository.workload["seed"].repository_url
  web_image_digest                 = var.web_image_digest
  gateway_image_digest             = var.gateway_image_digest
  was_image_digest                 = var.was_image_digest
  seed_image_digest                = var.seed_image_digest
  web_sentinel_parameter_name      = aws_ssm_parameter.web_bootstrap_sentinel[0].name
  web_sentinel_parameter_arn       = aws_ssm_parameter.web_bootstrap_sentinel[0].arn
  canary_object_version_id         = local.attachments_enabled ? var.canary_object_version_id : "bootstrap-pending"
  rds_endpoint                     = module.data[0].db_endpoint
  was_d1_reader_secret_arn         = aws_secretsmanager_secret.was_d1_reader[0].arn
  rds_master_secret_arn            = module.data[0].master_user_secret_arn
  enable_seed_master_secret_read   = var.enable_seed_master_secret_read
  canary_bucket_name               = var.canary_bucket_name
  canary_object_key                = var.canary_object_key
  nginx_modsecurity_log_group_name = module.observability[0].source_log_group_names["nginx_modsecurity"]
  web_log_group_name               = module.observability[0].source_log_group_names["web"]
  d0_envelope_log_group_name       = module.observability[0].source_log_group_names["d0_envelope"]
  was_log_group_name               = module.observability[0].source_log_group_names["was"]
  host_log_group_name              = module.observability[0].source_log_group_names["host"]
  tags                             = local.tags

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

}

resource "aws_secretsmanager_secret" "was_d1_reader" {
  count                   = local.substrate_enabled ? 1 : 0
  name                    = "argus/base/was/d1-reader"
  recovery_window_in_days = 0
  tags                    = merge(local.tags, { Component = "data", Purpose = "d1-synthetic-reader-runtime" })
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
}

resource "terraform_data" "observation_source_attachments" {
  count = local.attachments_enabled ? 1 : 0
  input = {
    canary_version_id = var.canary_object_version_id
    canary_object_arn = "arn:aws:s3:::${var.canary_bucket_name}/${var.canary_object_key}"
  }

  depends_on = [module.observability, module.edge, module.compute, module.data, module.canary]
}

resource "terraform_data" "evidence_cleanup_contract" {
  input = {
    teardown_authorized             = var.teardown_authorized
    evidence_cleanup_authorized     = var.evidence_cleanup_authorized
    evidence_cross_review_reference = var.evidence_cross_review_reference
    force_destroy_default           = false
  }
  lifecycle {
    precondition {
      condition     = !var.evidence_cleanup_authorized || (var.teardown_authorized && can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$", var.evidence_cross_review_reference)))
      error_message = "Evidence cleanup requires authorized teardown and a recorded cross-review reference."
    }
  }
}
