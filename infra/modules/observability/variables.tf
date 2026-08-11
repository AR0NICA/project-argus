variable "project" { type = string }
variable "environment" { type = string }
variable "name_prefix" { type = string }
variable "aws_account_id" { type = string }
variable "vpc_id" {
  type    = string
  default = ""
}
variable "evidence_bucket_name" { type = string }
variable "alb_access_log_bucket_name" { type = string }
variable "alb_access_log_prefix" {
  type    = string
  default = "alb"
}
variable "retention_in_days" {
  type    = number
  default = 30
}
variable "enable_s3_getobject_data_events" {
  type    = bool
  default = false
}
variable "enable_vpc_flow_logs" {
  type    = bool
  default = false
}
variable "s3_getobject_resource_arn" {
  type    = string
  default = ""
}
variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  common_tags = merge(var.tags, {
    Project     = var.project
    Environment = var.environment
    ManagedBy   = "IaC"
    Component   = "observability"
  })
  log_sources = toset(["nginx_modsecurity", "d0_envelope", "web", "was", "host", "vpc_flow", "cloudtrail"])
}
