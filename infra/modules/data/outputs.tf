output "db_instance_id" { value = aws_db_instance.this.id }
output "db_endpoint" { value = aws_db_instance.this.address }
output "master_user_secret_arn" {
  value     = aws_db_instance.this.master_user_secret[0].secret_arn
  sensitive = true
}
output "native_cloudwatch_log_group_names" {
  value = [for log_type in ["error", "general", "slowquery"] : aws_cloudwatch_log_group.native[log_type].name]
}
