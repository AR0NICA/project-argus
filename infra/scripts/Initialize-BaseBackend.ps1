[CmdletBinding()]
param(
    [switch]$Apply,
    [string]$AwsProfile = "PowerCodex"
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
$scriptRoot = Split-Path -Parent $PSScriptRoot
$bootstrapDir = Join-Path $scriptRoot "bootstrap"
$env:AWS_PROFILE = $AwsProfile

$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
Assert-NativeSuccess "AWS identity check"
if ($identity.Account -ne "962419263587") {
    throw "Refusing bootstrap for AWS account $($identity.Account). BASE requires 962419263587."
}

terraform -chdir=$bootstrapDir init -input=false
Assert-NativeSuccess "Bootstrap Terraform init"
terraform -chdir=$bootstrapDir plan -input=false -out=bootstrap.tfplan
Assert-NativeSuccess "Bootstrap Terraform plan"

if (-not $Apply) {
    Write-Output "Bootstrap plan created. Re-run with -Apply only after reviewing bootstrap.tfplan."
    exit 0
}

terraform -chdir=$bootstrapDir apply -input=false bootstrap.tfplan
Assert-NativeSuccess "Bootstrap Terraform apply"
Write-Output "Bootstrap complete. Configure infra/base with backend.hcl.example and run terraform init -reconfigure."
