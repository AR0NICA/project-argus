mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  aws_region               = "ap-northeast-2"
  allowed_test_cidrs       = ["198.51.100.10/32"]
  builder_parent_ami_id    = "ami-00000000000000000"
  gateway_image_digest     = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  web_image_digest         = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  was_image_digest         = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  seed_image_digest        = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  canary_object_version_id = "synthetic-version-id"
  budget_alert_email       = "terraform-test@example.invalid"
  owner                    = "terraform-test"
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

  override_data {
    target = data.terraform_remote_state.current_base[0]
    values = {
      outputs = { deployment_phase = "network" }
    }
  }

  variables {
    deployment_phase = "evidence"
  }

  assert {
    condition = output.frozen_observability_bucket_names == {
      evidence        = "argus-base-d1-evidence-ap-northeast-2-962419263587"
      alb_access_logs = "argus-base-alb-access-ap-northeast-2-962419263587"
    }
    error_message = "BASE observability bucket names must remain code-derived and frozen."
  }

  assert {
    condition     = toset(output.artifact_repository_names) == toset(["gateway", "seed", "was", "web"])
    error_message = "Evidence phase must create all immutable workload and seed repositories before substrate digests are required."
  }
}

run "reject_phase_jump" {
  command = plan

  override_data {
    target = data.terraform_remote_state.current_base[0]
    values = {
      outputs = { deployment_phase = "network" }
    }
  }

  variables {
    deployment_phase = "substrate"
  }

  expect_failures = [terraform_data.d0_guard]
}

run "substrate" {
  command = plan

  override_data {
    target = data.terraform_remote_state.current_base[0]
    values = {
      outputs = { deployment_phase = "image" }
    }
  }

  variables {
    deployment_phase = "substrate"
  }

  assert {
    condition     = !output.seed_contract.temporary_master_secret_read && output.seed_contract.runtime_starts_after_seed
    error_message = "Normal substrate must keep master-secret access disabled and wait for the fixed seed path."
  }

  assert {
    condition     = output.workload_artifacts.gateway.image_digest == var.gateway_image_digest
    error_message = "Substrate must preserve the reviewed gateway image digest in the workload contract."
  }

  assert {
    condition     = output.audit_node_identity_contract.exact_match
    error_message = "The WAS auditd node identity must exactly match the collector host ID."
  }
}

run "image" {
  command = plan

  override_data {
    target = data.terraform_remote_state.current_base[0]
    values = {
      outputs = { deployment_phase = "evidence" }
    }
  }

  variables {
    deployment_phase = "image"
  }
}

run "attachments" {
  command = plan

  override_data {
    target = data.terraform_remote_state.current_base[0]
    values = {
      outputs = { deployment_phase = "substrate" }
    }
  }

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
