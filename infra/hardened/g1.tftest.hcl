mock_provider "aws" {}

variables {
  deployment_phase    = "evidence"
  aws_region          = "ap-northeast-2"
  allowed_account_ids = ["123456789012"]
  availability_zones  = ["ap-northeast-2a", "ap-northeast-2c"]
  allowed_test_cidrs  = ["198.51.100.10/32"]
  owner               = "terraform-test"
}

run "frozen_observability_bucket_names" {
  command = plan

  assert {
    condition = output.frozen_observability_bucket_names == {
      evidence        = "argus-hardened-d1-evidence-ap-northeast-2-123456789012"
      alb_access_logs = "argus-hardened-alb-access-ap-northeast-2-123456789012"
    }
    error_message = "HARDENED observability bucket names must remain code-derived and frozen."
  }
}
