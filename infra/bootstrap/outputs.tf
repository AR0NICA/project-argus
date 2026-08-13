output "state_bucket_name" { value = aws_s3_bucket.terraform_state.id }
output "base_backend_config" {
  value = {
    bucket       = aws_s3_bucket.terraform_state.id
    key          = "argus/base/terraform.tfstate"
    region       = var.aws_region
    encrypt      = true
    use_lockfile = true
  }
}
