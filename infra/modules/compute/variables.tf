variable "name_prefix" { type = string }
variable "web_ami_id" { type = string }
variable "was_ami_id" { type = string }
variable "web_instance_type" { type = string }
variable "was_instance_type" { type = string }
variable "web_subnet_id" { type = string }
variable "was_subnet_id" { type = string }
variable "was_private_ip" { type = string }
variable "web_security_group_id" { type = string }
variable "was_security_group_id" { type = string }
variable "web_target_group_arn" { type = string }
variable "web_port" { type = number }
variable "web_log_group_arns" { type = list(string) }
variable "was_log_group_arns" { type = list(string) }
variable "aws_region" {
  type    = string
  default = ""
}
variable "ecr_registry" {
  type    = string
  default = ""
}
variable "gateway_ecr_repository_arn" {
  type    = string
  default = ""
}
variable "gateway_ecr_repository_url" {
  type    = string
  default = ""
}
variable "web_ecr_repository_arn" {
  type    = string
  default = ""
}
variable "web_ecr_repository_url" {
  type    = string
  default = ""
}
variable "was_ecr_repository_arn" {
  type    = string
  default = ""
}
variable "was_ecr_repository_url" {
  type    = string
  default = ""
}
variable "seed_ecr_repository_arn" {
  type    = string
  default = ""
}
variable "seed_ecr_repository_url" {
  type    = string
  default = ""
}
variable "web_image_digest" {
  type    = string
  default = ""
}
variable "gateway_image_digest" {
  type    = string
  default = ""
}
variable "was_image_digest" {
  type    = string
  default = ""
}
variable "seed_image_digest" {
  type    = string
  default = ""
}
variable "web_sentinel_parameter_name" {
  type    = string
  default = ""
}
variable "web_sentinel_parameter_arn" {
  type    = string
  default = ""
}
variable "canary_object_version_id" {
  type    = string
  default = ""
}
variable "rds_endpoint" {
  type    = string
  default = ""
}
variable "was_d1_reader_secret_arn" {
  type    = string
  default = ""
}
variable "rds_master_secret_arn" {
  type    = string
  default = ""
}
variable "enable_seed_master_secret_read" {
  type    = bool
  default = false
}
variable "canary_bucket_name" {
  type    = string
  default = ""
}
variable "canary_object_key" {
  type    = string
  default = ""
}
variable "nginx_modsecurity_log_group_name" {
  type    = string
  default = ""
}
variable "web_log_group_name" {
  type    = string
  default = ""
}
variable "d0_envelope_log_group_name" {
  type    = string
  default = ""
}
variable "was_log_group_name" {
  type    = string
  default = ""
}
variable "host_log_group_name" {
  type    = string
  default = ""
}
variable "tags" { type = map(string) }
