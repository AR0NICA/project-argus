[CmdletBinding()]
param(
    [ValidateSet("network", "evidence", "image", "substrate", "attachments")]
    [string]$Phase = "network",
    [string]$VarFile = "terraform.tfvars",
    [string]$AwsProfile = "PowerCodex"
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
$baseDir = Join-Path (Split-Path -Parent $PSScriptRoot) "base"
$env:AWS_PROFILE = $AwsProfile
$publicIp = (Invoke-RestMethod -Uri "https://checkip.amazonaws.com").Trim()
$parsedIp = [System.Net.IPAddress]::Parse($publicIp)
if ($parsedIp.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw "The execution-time address is not a public IPv4 address."
}
$clientCidr = "$publicIp/32"

if (-not (Test-Path (Join-Path $baseDir $VarFile))) {
    throw "Missing ignored local variable file: $VarFile. Copy terraform.tfvars.example first."
}

terraform "-chdir=$baseDir" init "-input=false" "-backend-config=backend.hcl"
Assert-NativeSuccess "BASE Terraform init"
terraform "-chdir=$baseDir" plan "-input=false" "-var-file=$VarFile" "-var=deployment_phase=$Phase" "-var=allowed_test_cidrs=[`"$clientCidr`"]" "-out=base.tfplan"
Assert-NativeSuccess "BASE Terraform plan"
Write-Output "Planned $Phase using execution-time client CIDR $clientCidr. Review infra/base/base.tfplan before any apply."
