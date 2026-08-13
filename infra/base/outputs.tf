output "deployment_phase" { value = var.deployment_phase }
output "teardown_contract" {
  value = {
    authorized                         = var.teardown_authorized
    mode                               = var.teardown_mode
    alb_deletion_protection_enabled    = !var.teardown_authorized
    rds_deletion_protection_enabled    = !var.teardown_authorized
    skip_final_snapshot                = var.teardown_authorized && var.teardown_mode == "skip_final_snapshot"
    final_snapshot_identifier_required = var.teardown_authorized && var.teardown_mode == "final_snapshot"
    final_snapshot_identifier          = var.teardown_authorized && var.teardown_mode == "final_snapshot" ? var.teardown_final_snapshot_identifier : null
  }
}
output "state_key_example" { value = "argus/base/terraform.tfstate" }
output "frozen_observability_bucket_names" {
  value = local.network_enabled ? {
    evidence        = local.evidence_bucket_name
    alb_access_logs = local.alb_access_log_bucket_name
  } : null
}
output "vpc_id" { value = try(module.network[0].vpc_id, null) }
output "security_group_ids" { value = try(module.network[0].security_group_ids, null) }
output "private_subnet_ids" { value = try({ web = module.network[0].web_subnet_ids, was = module.network[0].was_subnet_ids, data = module.network[0].data_subnet_ids }, null) }
output "alb_dns_name" { value = try(module.edge[0].alb_dns_name, null) }
output "base_hostname" { value = local.substrate_enabled ? var.hostname : null }
output "base_alb_alias_fqdn" { value = try(aws_route53_record.alb[0].fqdn, null) }
output "runtime_ami" {
  value = local.image_enabled ? {
    ami_id        = module.image_builder[0].ami_id
    image_arn     = module.image_builder[0].image_arn
    parent_ami_id = module.image_builder[0].parent_ami_id
  } : null
}
output "acm_certificate_arn" {
  value     = try(aws_acm_certificate_validation.base[0].certificate_arn, null)
  sensitive = true
}
output "rds_endpoint" {
  value     = try(module.data[0].db_endpoint, null)
  sensitive = true
}
output "rds_master_secret_arn" {
  value     = try(module.data[0].master_user_secret_arn, null)
  sensitive = true
}
output "was_d1_reader_secret_arn" {
  value     = try(aws_secretsmanager_secret.was_d1_reader[0].arn, null)
  sensitive = true
}
output "canary_bucket_arn" { value = try(module.canary[0].bucket_arn, null) }
output "evidence_source_log_group_names" {
  value = try(module.observability[0].source_log_group_names, null)
}

output "rds_native_cloudwatch_log_group_names" {
  value = try(module.data[0].native_cloudwatch_log_group_names, null)
}
output "workload_artifacts" {
  value = local.substrate_enabled ? {
    web = {
      repository_url = aws_ecr_repository.workload["web"].repository_url
      image_digest   = var.web_image_digest
      instance_id    = module.compute[0].web_instance_id
    }
    gateway = {
      repository_url = aws_ecr_repository.workload["gateway"].repository_url
      image_digest   = var.gateway_image_digest
    }
    seed = {
      repository_url = aws_ecr_repository.workload["seed"].repository_url
      image_digest   = var.seed_image_digest
    }
    was = {
      repository_url = aws_ecr_repository.workload["was"].repository_url
      image_digest   = var.was_image_digest
      instance_id    = module.compute[0].was_instance_id
    }
  } : null
}
output "collector_host_ids" {
  value = local.substrate_enabled ? {
    web = module.compute[0].web_instance_id
    was = module.compute[0].was_instance_id
  } : null
}
output "audit_node_identity_contract" {
  value = local.substrate_enabled ? {
    was_auditd_node = module.compute[0].was_instance_id
    collector_host  = module.compute[0].was_instance_id
    exact_match     = true
  } : null
}
output "artifact_repository_names" {
  value = local.artifact_enabled ? sort(keys(aws_ecr_repository.workload)) : []
}
output "seed_contract" {
  value = local.substrate_enabled ? {
    repository_url                     = aws_ecr_repository.workload["seed"].repository_url
    image_digest                       = var.seed_image_digest
    temporary_master_secret_read       = var.enable_seed_master_secret_read
    temporary_reader_secret_write      = var.enable_seed_master_secret_read
    runtime_starts_after_seed          = true
    runtime_master_secret_read_default = false
  } : null
}
output "collector_targets" {
  value = local.evidence_enabled ? {
    cloudtrail_name              = module.observability[0].cloudtrail_name
    cloudtrail_s3_prefix         = module.observability[0].cloudtrail_s3_prefix
    evidence_bucket              = module.observability[0].evidence_bucket_name
    alb_access_log_bucket        = module.observability[0].alb_access_log_bucket_name
    source_log_groups            = module.observability[0].source_log_group_names
    rds_native_log_groups        = try(module.data[0].native_cloudwatch_log_group_names, [])
    vpc_flow_log_id              = module.observability[0].vpc_flow_log_id
    vpc_flow_aggregation_seconds = 60
  } : null
}
output "evidence_cleanup_contract" {
  value = {
    force_destroy_default           = false
    cross_review_required           = true
    evidence_cleanup_authorized     = var.evidence_cleanup_authorized
    evidence_cross_review_reference = var.evidence_cross_review_reference
  }
}
