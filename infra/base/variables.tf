variable "deployment_phase" {
  type    = string
  default = "disabled"

  validation {
    condition     = contains(["disabled", "network", "evidence", "image", "substrate", "attachments"], var.deployment_phase)
    error_message = "deployment_phase must advance through disabled, network, evidence, image, substrate, or attachments."
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

  validation {
    condition     = var.aws_region == "ap-northeast-2"
    error_message = "BASE is approved only in ap-northeast-2."
  }
}

variable "allowed_test_cidrs" {
  type    = list(string)
  default = []

  validation {
    condition     = length(var.allowed_test_cidrs) == 0 || (length(var.allowed_test_cidrs) == 1 && can(cidrhost(var.allowed_test_cidrs[0], 0)) && endswith(var.allowed_test_cidrs[0], "/32"))
    error_message = "allowed_test_cidrs must be empty before execution or exactly one public IPv4 /32."
  }
}

variable "hostname" {
  type    = string
  default = "argus-base.ar0nica.xyz"

  validation {
    condition     = var.hostname == "argus-base.ar0nica.xyz"
    error_message = "BASE hostname is fixed to argus-base.ar0nica.xyz."
  }
}

variable "hosted_zone_name" {
  type    = string
  default = "ar0nica.xyz"
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

variable "builder_parent_ami_id" {
  type    = string
  default = ""
}
variable "image_builder_component_version" {
  type    = string
  default = "1.0.0"
}
variable "image_builder_recipe_version" {
  type    = string
  default = "1.0.1"
}

variable "web_sentinel_value" {
  type      = string
  default   = "ARGUS_BASE_WEB_BOOTSTRAP_SENTINEL_V1"
  sensitive = true
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
  default = "argus-base-canary-ap-northeast-2-962419263587"

  validation {
    condition     = var.canary_bucket_name == "argus-base-canary-ap-northeast-2-962419263587"
    error_message = "BASE canary bucket name is fixed by the approved substrate contract."
  }
}

variable "canary_object_key" {
  type    = string
  default = "canary/was-bundle.json"
}

variable "canary_object_version_id" {
  type    = string
  default = ""
}

variable "evidence_retention_in_days" {
  type    = number
  default = 30
}

variable "enable_budget" {
  type    = bool
  default = true
}

variable "monthly_limit_usd" {
  type    = number
  default = 25
}

variable "budget_alert_email" {
  type    = string
  default = ""
}

variable "evidence_cleanup_authorized" {
  type    = bool
  default = false
}

variable "enable_seed_master_secret_read" {
  type    = bool
  default = false
}

variable "evidence_cross_review_reference" {
  type    = string
  default = ""
}

variable "owner" {
  type    = string
  default = "TODO"
}
