[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$EvidenceBucket,
    [Parameter(Mandatory)]
    [string]$AlbAccessLogBucket,
    [Parameter(Mandatory)]
    [string]$CanaryBucket,
    [Parameter(Mandatory)]
    [ValidatePattern("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")]
    [string]$CrossReviewReference,
    [string]$AwsProfile = "PowerCodex",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$env:AWS_PROFILE = $AwsProfile
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
function Assert-BaseBucket([string]$Bucket, [string]$Pattern) {
    if ($Bucket -notmatch $Pattern) { throw "Refusing cleanup for an unexpected bucket name: $Bucket" }
    $location = aws s3api get-bucket-location --bucket $Bucket --output json | ConvertFrom-Json
    Assert-NativeSuccess "Bucket region lookup for $Bucket"
    $region = if ($null -eq $location.LocationConstraint) { "us-east-1" } else { $location.LocationConstraint }
    if ($region -ne "ap-northeast-2") { throw "Refusing cleanup for $Bucket outside ap-northeast-2." }
}
function Remove-AllBucketVersions([string]$Bucket) {
    while ($true) {
        $page = aws s3api list-object-versions --bucket $Bucket --max-keys 1000 --output json | ConvertFrom-Json
        Assert-NativeSuccess "Version enumeration for $Bucket"
        $objects = @()
        foreach ($item in @($page.Versions) + @($page.DeleteMarkers)) { $objects += @{ Key = $item.Key; VersionId = $item.VersionId } }
        if ($objects.Count -eq 0) { break }
        $payload = @{ Objects = $objects; Quiet = $true } | ConvertTo-Json -Depth 4 -Compress
        $payloadPath = Join-Path $env:TEMP ("argus-delete-" + [guid]::NewGuid().ToString("N") + ".json")
        try {
            [IO.File]::WriteAllText($payloadPath, $payload, [Text.UTF8Encoding]::new($false))
            $deletion = aws s3api delete-objects --bucket $Bucket --delete "file://$payloadPath" --output json | ConvertFrom-Json
            Assert-NativeSuccess "Version deletion for $Bucket"
            if (@($deletion.Errors).Count -gt 0) { throw "S3 returned per-object deletion errors for $Bucket." }
        } finally { if (Test-Path -LiteralPath $payloadPath) { Remove-Item -LiteralPath $payloadPath -Force } }
    }
}

Assert-BaseBucket $EvidenceBucket "^argus-base-d1-evidence-ap-northeast-2-962419263587$"
Assert-BaseBucket $AlbAccessLogBucket "^argus-base-alb-access-ap-northeast-2-962419263587$"
Assert-BaseBucket $CanaryBucket "^argus-base-canary-ap-northeast-2-962419263587$"
foreach ($bucket in @($EvidenceBucket, $AlbAccessLogBucket, $CanaryBucket)) {
    Write-Output "Validated version-aware cleanup target: $bucket"
}
if (-not $Execute) {
    Write-Output "Dry contract only. Preserve evidence until cross-review $CrossReviewReference is recorded and re-run with -Execute."
    exit 0
}

$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
Assert-NativeSuccess "AWS identity check"
if ($identity.Account -ne "962419263587") { throw "Refusing cleanup outside account 962419263587." }
foreach ($bucket in @($EvidenceBucket, $AlbAccessLogBucket, $CanaryBucket)) {
    Remove-AllBucketVersions $bucket
}
Write-Output "All object versions and delete markers were removed after cross-review $CrossReviewReference. Buckets remain protected by Terraform force_destroy=false."
