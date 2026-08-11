variable "deployment_phase" {
  type    = string
  default = "disabled"

  validation {
    condition     = contains(["disabled", "network", "evidence", "substrate", "attachments"], var.deployment_phase)
    error_message = "deployment_phase must advance through disabled, network, evidence, substrate, or attachments."
  }
}

variable "teardown_authorized" {
  type    = bool
  default = false
}

variable "teardown_mode" {
  type    = string
  default = "protected"

  validation {
    condition     = contains(["protected", "final_snapshot", "skip_final_snapshot"], var.teardown_mode)
    error_message = "teardown_mode must be protected, final_snapshot, or skip_final_snapshot."
  }
}

variable "teardown_final_snapshot_identifier" {
  type    = string
  default = ""
}

variable "aws_region" {
  type    = string
  default = "ap-northeast-2"
}

variable "allowed_account_ids" {
  type    = list(string)
  default = []
}

variable "availability_zones" {
  type    = list(string)
  default = []
}

variable "allowed_test_cidrs" {
  type    = list(string)
  default = []
}

variable "tls_certificate_arn" {
  type    = string
  default = ""
}

variable "web_ami_id" {
  type    = string
  default = ""
}

variable "was_ami_id" {
  type    = string
  default = ""
}

variable "web_instance_type" {
  type    = string
  default = "t3.small"
}

variable "was_instance_type" {
  type    = string
  default = "t3.small"
}

variable "rds_instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "rds_allocated_storage" {
  type    = number
  default = 20
}

variable "canary_bucket_name" {
  type    = string
  default = ""
}

variable "canary_object_key" {
  type    = string
  default = "canary/was-bundle.json"
}

variable "canary_object_version_id" {
  type    = string
  default = ""
}

variable "evidence_bucket_name" {
  type    = string
  default = ""
}

variable "alb_access_log_bucket_name" {
  type    = string
  default = ""
}

variable "evidence_retention_in_days" {
  type    = number
  default = 30
}

variable "enable_budget" {
  type    = bool
  default = false
}

variable "monthly_limit_usd" {
  type    = number
  default = 25
}

variable "budget_alert_email" {
  type    = string
  default = ""
}

variable "owner" {
  type    = string
  default = "TODO"
}
