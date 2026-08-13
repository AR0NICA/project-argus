[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")] [string]$CrossReviewReference,
    [string]$AwsProfile = "PowerCodex",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
$env:AWS_PROFILE = $AwsProfile
$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
Assert-NativeSuccess "AWS identity check"
if ($identity.Account -ne "962419263587") { throw "Refusing ECR cleanup outside account 962419263587." }
$repositories = @("argus-base-gateway", "argus-base-web", "argus-base-was", "argus-base-seed")
foreach ($repository in $repositories) {
    $details = aws ecr describe-repositories --repository-names $repository --region ap-northeast-2 --output json | ConvertFrom-Json
    Assert-NativeSuccess "ECR repository lookup for $repository"
    if ($details.repositories.Count -ne 1 -or $details.repositories[0].repositoryName -ne $repository) { throw "Unexpected ECR repository response for $repository." }
}
if (-not $Execute) { Write-Output "Dry contract only. ECR image deletion requires cross-review $CrossReviewReference and explicit -Execute."; exit 0 }
foreach ($repository in $repositories) {
    while ($true) {
        $images = aws ecr list-images --repository-name $repository --region ap-northeast-2 --filter tagStatus=ANY --max-results 1000 --output json | ConvertFrom-Json
        Assert-NativeSuccess "ECR image enumeration for $repository"
        $imageIds = @($images.imageIds)
        if ($imageIds.Count -eq 0) { break }
        for ($offset = 0; $offset -lt $imageIds.Count; $offset += 100) {
            $batch = @($imageIds[$offset..([Math]::Min($offset + 99, $imageIds.Count - 1))]) | ConvertTo-Json -Compress
            $payloadPath = Join-Path $env:TEMP ("argus-ecr-delete-" + [guid]::NewGuid().ToString("N") + ".json")
            try {
                [IO.File]::WriteAllText($payloadPath, $batch, [Text.UTF8Encoding]::new($false))
                $deletion = aws ecr batch-delete-image --repository-name $repository --region ap-northeast-2 --image-ids "file://$payloadPath" --output json | ConvertFrom-Json
                Assert-NativeSuccess "ECR image deletion for $repository"
                if (@($deletion.failures).Count -gt 0) { throw "ECR returned per-image deletion failures for $repository." }
            } finally { if (Test-Path -LiteralPath $payloadPath) { Remove-Item -LiteralPath $payloadPath -Force } }
        }
    }
}
Write-Output "All exact BASE ECR image digests were removed after cross-review $CrossReviewReference. Terraform repository force_delete remains false."
