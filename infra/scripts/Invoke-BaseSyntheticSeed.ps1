[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$WasInstanceId,
    [Parameter(Mandatory)] [string]$RdsEndpoint,
    [Parameter(Mandatory)] [string]$RdsMasterSecretArn,
    [Parameter(Mandatory)] [string]$WasD1ReaderSecretArn,
    [Parameter(Mandatory)] [ValidatePattern("^[0-9]{12}\.dkr\.ecr\.ap-northeast-2\.amazonaws\.com/argus-base-seed@sha256:[a-f0-9]{64}$")] [string]$SeedImage,
    [string]$AwsProfile = "PowerCodex",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
if (-not $Execute) { throw "Fixed seed requires explicit -Execute after reviewing the temporary seed-only IAM plan." }
if ($WasInstanceId -notmatch "^i-[a-f0-9]{8,17}$" -or $RdsEndpoint -notmatch "^[a-z0-9.-]+\.rds\.amazonaws\.com$" -or $RdsMasterSecretArn -notmatch "^arn:aws:secretsmanager:ap-northeast-2:962419263587:secret:" -or $WasD1ReaderSecretArn -notmatch "^arn:aws:secretsmanager:ap-northeast-2:962419263587:secret:") { throw "Seed targets are outside the approved BASE boundary." }

$env:AWS_PROFILE = $AwsProfile
$command = "set -euo pipefail; /usr/local/sbin/argus-ecr-login; docker pull '$SeedImage'; docker run --rm --network host -e AWS_REGION=ap-northeast-2 -e ARGUS_RDS_ENDPOINT='$RdsEndpoint' -e ARGUS_RDS_MASTER_SECRET_ARN='$RdsMasterSecretArn' -e ARGUS_D1_READER_SECRET_ARN='$WasD1ReaderSecretArn' '$SeedImage'; systemctl start argus-d1-was.service"
$parameters = @{ commands = @($command) } | ConvertTo-Json -Compress
$result = aws ssm send-command --document-name "AWS-RunShellScript" --instance-ids $WasInstanceId --parameters $parameters --comment "ARGUS BASE fixed synthetic D1 seed container" --output json | ConvertFrom-Json
Assert-NativeSuccess "SSM seed command submission"
$commandId = $result.Command.CommandId
do {
    Start-Sleep -Seconds 5
    $invocation = aws ssm get-command-invocation --command-id $commandId --instance-id $WasInstanceId --output json 2>$null | ConvertFrom-Json
    Assert-NativeSuccess "SSM seed command status lookup"
} while ($invocation.Status -in @("Pending", "InProgress", "Delayed"))
if ($invocation.Status -ne "Success") {
    throw "Fixed seed command $commandId ended with status $($invocation.Status). No command output is printed because it may contain operational metadata."
}
Write-Output "Fixed seed completed: $commandId. Plan and apply enable_seed_master_secret_read=false before the D1 health gate."
