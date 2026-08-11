mock_provider "aws" {}

variables {
  aws_region                 = "ap-northeast-2"
  allowed_account_ids        = ["123456789012"]
  availability_zones         = ["ap-northeast-2a", "ap-northeast-2c"]
  allowed_test_cidrs         = ["198.51.100.10/32"]
  evidence_bucket_name       = "argus-base-evidence-test-123456789012"
  alb_access_log_bucket_name = "argus-base-alb-test-123456789012"
  tls_certificate_arn        = "arn:aws:acm:ap-northeast-2:123456789012:certificate/00000000-0000-0000-0000-000000000000"
  web_ami_id                 = "ami-00000000000000000"
  was_ami_id                 = "ami-00000000000000000"
  canary_bucket_name         = "argus-base-canary-test-123456789012"
  canary_object_version_id   = "synthetic-version-id"
  owner                      = "terraform-test"
}

run "disabled" {
  command = plan

  variables {
    deployment_phase = "disabled"
  }

  assert {
    condition     = output.deployment_phase == "disabled"
    error_message = "The default-safe phase must remain disabled."
  }
}

run "network" {
  command = plan

  variables {
    deployment_phase = "network"
  }
}

run "evidence" {
  command = plan

  variables {
    deployment_phase = "evidence"
  }
}

run "substrate" {
  command = plan

  variables {
    deployment_phase = "substrate"
  }
}

run "attachments" {
  command = plan

  variables {
    deployment_phase = "attachments"
  }
}

run "authorized_final_snapshot_teardown" {
  command = plan

  variables {
    deployment_phase                   = "substrate"
    teardown_authorized                = true
    teardown_mode                      = "final_snapshot"
    teardown_final_snapshot_identifier = "argus-base-teardown-test-20260811-001"
  }

  assert {
    condition     = output.teardown_contract.mode == "final_snapshot" && !output.teardown_contract.alb_deletion_protection_enabled && !output.teardown_contract.rds_deletion_protection_enabled
    error_message = "Authorized final-snapshot teardown must remove only the deletion-protection gates."
  }
}

run "authorized_skip_final_snapshot_teardown" {
  command = plan

  variables {
    deployment_phase    = "substrate"
    teardown_authorized = true
    teardown_mode       = "skip_final_snapshot"
  }

  assert {
    condition     = output.teardown_contract.skip_final_snapshot && !output.teardown_contract.final_snapshot_identifier_required
    error_message = "Synthetic-data teardown must explicitly select skip_final_snapshot."
  }
}
