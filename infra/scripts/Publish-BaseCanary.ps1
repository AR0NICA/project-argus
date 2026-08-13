[CmdletBinding()]
param(
    [string]$CanaryFile = "fixtures/d1-canary.json",
    [string]$AwsProfile = "PowerCodex",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
if (-not $Execute) { throw "Canary publication requires explicit -Execute after reviewing the fixed fixture." }
if (-not (Test-Path -LiteralPath $CanaryFile -PathType Leaf)) { throw "Fixed canary fixture is missing: $CanaryFile" }
$env:AWS_PROFILE = $AwsProfile
$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
Assert-NativeSuccess "AWS identity check"
if ($identity.Account -ne "962419263587") { throw "Refusing canary publication outside account 962419263587." }
$bucket = "argus-base-canary-ap-northeast-2-962419263587"
$key = "canary/was-bundle.json"
$location = aws s3api get-bucket-location --bucket $bucket --output json | ConvertFrom-Json
Assert-NativeSuccess "Canary bucket region lookup"
if ($location.LocationConstraint -ne "ap-northeast-2") { throw "Refusing canary publication outside ap-northeast-2." }
$digest = (Get-FileHash -LiteralPath $CanaryFile -Algorithm SHA256).Hash.ToLowerInvariant()
$upload = aws s3api put-object --bucket $bucket --key $key --body $CanaryFile --region ap-northeast-2 --output json | ConvertFrom-Json
Assert-NativeSuccess "Canary upload"
if ($upload.VersionId -notmatch "\S") { throw "Canary upload did not return a version ID." }
Write-Output "canary_bucket=$bucket"
Write-Output "canary_key=$key"
Write-Output "canary_sha256=$digest"
Write-Output "canary_version_id=$($upload.VersionId)"
