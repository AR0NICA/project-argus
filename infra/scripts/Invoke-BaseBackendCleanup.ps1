[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })] [string]$BaseStateExport,
    [Parameter(Mandatory)] [ValidatePattern("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")] [string]$CrossReviewReference,
    [switch]$BaseDestroyConfirmed,
    [string]$AwsProfile = "PowerCodex",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
if (-not $BaseDestroyConfirmed) { throw "Backend cleanup requires explicit confirmation that BASE destroy completed after exporting state." }
$stateFile = Get-Item -LiteralPath $BaseStateExport
if ($stateFile.Length -lt 2) { throw "The BASE state export is empty." }
$bucket = "argus-terraform-state-ap-northeast-2-962419263587"
$allowedKeys = @("argus/base/terraform.tfstate", "argus/base/terraform.tfstate.tflock")
$env:AWS_PROFILE = $AwsProfile
$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
Assert-NativeSuccess "AWS identity check"
if ($identity.Account -ne "962419263587") { throw "Refusing backend cleanup outside account 962419263587." }
$location = aws s3api get-bucket-location --bucket $bucket --output json | ConvertFrom-Json
Assert-NativeSuccess "Backend bucket region lookup"
if ($location.LocationConstraint -ne "ap-northeast-2") { throw "Refusing backend cleanup outside ap-northeast-2." }
if (-not $Execute) { Write-Output "Dry contract only. Backend version/delete-marker cleanup requires cross-review $CrossReviewReference and explicit -Execute."; exit 0 }
while ($true) {
    $page = aws s3api list-object-versions --bucket $bucket --max-keys 1000 --output json | ConvertFrom-Json
    Assert-NativeSuccess "Backend version enumeration"
    $objects = @()
    foreach ($item in @($page.Versions) + @($page.DeleteMarkers)) {
        if ($null -eq $item) { continue }
        if ($item.Key -notin $allowedKeys -or [string]::IsNullOrWhiteSpace($item.VersionId)) {
            throw "Refusing unexpected or malformed backend version entry."
        }
        $objects += @{ Key = $item.Key; VersionId = $item.VersionId }
    }
    if ($objects.Count -eq 0) { break }
    $payloadPath = Join-Path $env:TEMP ("argus-backend-delete-" + [guid]::NewGuid().ToString("N") + ".json")
    try {
        $payload = @{ Objects = $objects; Quiet = $true } | ConvertTo-Json -Depth 4 -Compress
        [IO.File]::WriteAllText($payloadPath, $payload, [Text.UTF8Encoding]::new($false))
        $deletion = aws s3api delete-objects --bucket $bucket --delete "file://$payloadPath" --output json | ConvertFrom-Json
        Assert-NativeSuccess "Backend version deletion"
        if ($null -ne $deletion.Errors -and @($deletion.Errors).Count -gt 0) {
            throw "S3 returned per-object backend deletion errors."
        }
    } finally { if (Test-Path -LiteralPath $payloadPath) { Remove-Item -LiteralPath $payloadPath -Force } }
}
Write-Output "All backend object versions/delete markers were removed after state export, destroy confirmation, and cross-review $CrossReviewReference."
