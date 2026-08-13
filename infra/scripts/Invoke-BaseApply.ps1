[CmdletBinding()]
param(
    [ValidateSet("network", "evidence", "image", "substrate", "attachments")]
    [string]$Phase,
    [string]$VarFile = "terraform.tfvars",
    [string]$AwsProfile = "PowerCodex",
    [string]$BudgetAlertEmail,
    [switch]$Apply
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
if (-not $Apply) {
    throw "This command only applies with explicit -Apply after a reviewed saved plan."
}
if ([string]::IsNullOrWhiteSpace($BudgetAlertEmail)) {
    $BudgetAlertEmail = Read-Host "Enter the local budget alert email for the USD 25 monthly budget"
}
if ($BudgetAlertEmail -notmatch "^[^@\s]+@[^@\s]+\.[^@\s]+$") {
    throw "A valid budget alert email is required and is never written to a file by this script."
}

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

terraform -chdir=$baseDir init -input=false -backend-config=backend.hcl
Assert-NativeSuccess "BASE Terraform init"
terraform -chdir=$baseDir plan -input=false -var-file=$VarFile -var="deployment_phase=$Phase" -var="allowed_test_cidrs=[`"$clientCidr`"]" -var="budget_alert_email=$BudgetAlertEmail" -out=base.tfplan
Assert-NativeSuccess "BASE Terraform plan"
terraform -chdir=$baseDir show -no-color base.tfplan
Assert-NativeSuccess "BASE Terraform saved plan review"
$confirmation = Read-Host "Type APPLY-BASE-$Phase to apply the reviewed plan"
if ($confirmation -ne "APPLY-BASE-$Phase") {
    throw "Apply confirmation did not match. No resources were changed."
}
terraform -chdir=$baseDir apply -input=false base.tfplan
Assert-NativeSuccess "BASE Terraform apply"
