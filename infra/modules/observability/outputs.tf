output "evidence_bucket_name" { value = aws_s3_bucket.evidence.id }
output "evidence_bucket_arn" { value = aws_s3_bucket.evidence.arn }
output "evidence_kms_key_arn" { value = aws_kms_key.evidence.arn }
output "alb_access_log_bucket_name" { value = aws_s3_bucket.alb_access.id }
output "alb_access_log_bucket_arn" { value = aws_s3_bucket.alb_access.arn }
output "alb_access_log_prefix" { value = var.alb_access_log_prefix }
output "cloudtrail_arn" { value = aws_cloudtrail.d1.arn }
output "cloudtrail_name" { value = aws_cloudtrail.d1.name }
output "vpc_flow_log_id" { value = try(aws_flow_log.vpc[0].id, null) }
output "vpc_flow_log_role_arn" { value = aws_iam_role.flow.arn }
output "cloudtrail_log_group_name" { value = aws_cloudwatch_log_group.source["cloudtrail"].name }
output "cloudtrail_s3_prefix" { value = "s3://${aws_s3_bucket.evidence.id}/AWSLogs/${var.aws_account_id}/" }
output "source_log_group_arns" { value = { for source, group in aws_cloudwatch_log_group.source : source => group.arn } }
output "source_log_group_names" { value = { for source, group in aws_cloudwatch_log_group.source : source => group.name } }
output "workload_attachment_contract" {
  value = {
    alb_access_logs = {
      attachment_owner = "base-edge"
      destination      = "alb_access_log_bucket_name output"
      reason           = "ALB native access delivery uses the foundation SSE-S3 bucket, not CloudWatch Logs or the SSE-KMS evidence bucket"
      required_prefix  = "${var.alb_access_log_prefix}/AWSLogs/${var.aws_account_id}/"
    }
    rds_log_exports = {
      attachment_owner = "base-data"
      destination      = "native_cloudwatch_log_groups"
      name_prefix      = "/aws/rds/instance/<db-identifier>/"
      reason           = "RDS creates native export groups; this module does not precreate arbitrary /argus rds groups"
    }
  }
}
