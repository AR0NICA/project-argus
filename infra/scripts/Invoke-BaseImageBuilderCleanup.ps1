[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ImageArn,
    [Parameter(Mandatory)] [ValidatePattern("^[A-Za-z0-9][A-Za-z0-9._-]{7,127}$")] [string]$CrossReviewReference,
    [string]$AwsProfile = "PowerCodex",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
function Assert-NativeSuccess([string]$Operation) { if ($LASTEXITCODE -ne 0) { throw "$Operation failed with exit code $LASTEXITCODE." } }
if ($ImageArn -notmatch "^arn:aws:imagebuilder:ap-northeast-2:962419263587:image/argus-base-runtime/") { throw "Refusing cleanup for an unexpected Image Builder image ARN." }
$env:AWS_PROFILE = $AwsProfile
$identity = aws sts get-caller-identity --output json | ConvertFrom-Json
Assert-NativeSuccess "AWS identity check"
if ($identity.Account -ne "962419263587") { throw "Refusing Image Builder cleanup outside account 962419263587." }
$image = aws imagebuilder get-image --image-build-version-arn $ImageArn --region ap-northeast-2 --output json | ConvertFrom-Json
Assert-NativeSuccess "Image Builder image lookup"
$ami = @($image.image.outputResources.amis | Where-Object { $_.region -eq "ap-northeast-2" })
if ($ami.Count -ne 1 -or $ami[0].name -notmatch "^argus-base-runtime-") { throw "Unexpected Image Builder AMI output." }
if (-not $Execute) { Write-Output "Dry contract only. Image Builder AMI/snapshot cleanup requires cross-review $CrossReviewReference and explicit -Execute."; exit 0 }
$amiId = $ami[0].image
$imageDetails = aws ec2 describe-images --image-ids $amiId --region ap-northeast-2 --output json | ConvertFrom-Json
Assert-NativeSuccess "AMI block-device enumeration"
$snapshotIds = @($imageDetails.Images[0].BlockDeviceMappings | ForEach-Object { $_.Ebs.SnapshotId } | Where-Object { $_ })
aws ec2 deregister-image --image-id $amiId --region ap-northeast-2
Assert-NativeSuccess "AMI deregistration"
foreach ($snapshotId in $snapshotIds) {
    aws ec2 delete-snapshot --snapshot-id $snapshotId --region ap-northeast-2
    Assert-NativeSuccess "Snapshot deletion for $snapshotId"
}
Write-Output "Image Builder AMI $amiId and its exact captured snapshots were removed after cross-review $CrossReviewReference."
