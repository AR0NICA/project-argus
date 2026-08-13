[CmdletBinding()]
param(
    [Parameter(Mandatory)] [ValidatePattern("^[a-z0-9][a-z0-9._-]{0,127}$")] [string]$ImmutableTag,
    [string]$AwsProfile = "PowerCodex",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
if (-not $Execute) { throw "Image publication requires explicit -Execute after reviewing source and immutable tag $ImmutableTag." }
$env:AWS_PROFILE = $AwsProfile
$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
Assert-NativeSuccess "AWS identity check"
if ($identity.Account -ne "962419263587") { throw "Refusing image publication outside account 962419263587." }
$registry = "962419263587.dkr.ecr.ap-northeast-2.amazonaws.com"
aws ecr get-login-password --region ap-northeast-2 | docker login --username AWS --password-stdin $registry
Assert-NativeSuccess "ECR login"
$images = @(
    @{ Name = "gateway"; Dockerfile = "services/gateway/Dockerfile"; Context = "services/gateway" },
    @{ Name = "web"; Dockerfile = "services/web/Dockerfile"; Context = "services/web" },
    @{ Name = "was"; Dockerfile = "services/was/Dockerfile"; Context = "services/was" },
    @{ Name = "seed"; Dockerfile = "infra/seed/Dockerfile"; Context = "infra/seed" }
)
foreach ($image in $images) {
    $reference = "$registry/argus-base-$($image.Name):$ImmutableTag"
    docker buildx build --platform linux/amd64 --load --file $image.Dockerfile --tag $reference $image.Context
    Assert-NativeSuccess "linux/amd64 build for $($image.Name)"
    docker push $reference
    Assert-NativeSuccess "ECR push for $($image.Name)"
    $digest = aws ecr describe-images --repository-name "argus-base-$($image.Name)" --image-ids "imageTag=$ImmutableTag" --region ap-northeast-2 --query "imageDetails[0].imageDigest" --output text
    Assert-NativeSuccess "Digest lookup for $($image.Name)"
    if ($digest -notmatch "^sha256:[a-f0-9]{64}$") { throw "Digest lookup returned an invalid value for $($image.Name)." }
    Write-Output "$($image.Name)=$registry/argus-base-$($image.Name)@$digest"
}
