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
output "vpc_id" { value = try(module.network[0].vpc_id, null) }
output "security_group_ids" { value = try(module.network[0].security_group_ids, null) }
output "private_subnet_ids" { value = try({ web = module.network[0].web_subnet_ids, was = module.network[0].was_subnet_ids, data = module.network[0].data_subnet_ids }, null) }
output "alb_dns_name" { value = try(module.edge[0].alb_dns_name, null) }
output "rds_endpoint" {
  value     = try(module.data[0].db_endpoint, null)
  sensitive = true
}
output "canary_bucket_arn" { value = try(module.canary[0].bucket_arn, null) }
output "evidence_source_log_group_names" {
  value = try(module.observability[0].source_log_group_names, null)
}

output "rds_native_cloudwatch_log_group_names" {
  value = try(module.data[0].native_cloudwatch_log_group_names, null)
}
