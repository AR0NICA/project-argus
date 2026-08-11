[CmdletBinding()]
param([ValidateRange(1, 99)][int]$RunNumber = 1)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Windows PowerShell 5.1 converts any native-command stderr line into a terminating
# error when $ErrorActionPreference='Stop'. Docker/compose print normal progress
# ("Image ... Pulling/Building", "Container ... Stopping") to stderr, so run native
# tools with 'Continue' and judge success only by $LASTEXITCODE.
function Invoke-Native {
    param([Parameter(Mandatory)][scriptblock]$Command)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $prev }
}

# Windows PowerShell 5.1 `Set-Content -Encoding utf8` prepends a UTF-8 BOM, which
# breaks the exact byte/JSON contracts the WAS app and evidence validator enforce
# (json.loads chokes on a leading BOM). Write evidence as UTF-8 without a BOM.
function Write-Utf8NoBom {
    param([Parameter(Mandatory)][string]$Path, [AllowEmptyString()][string]$Text = '')
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Runtime blocker: Docker CLI/engine is not installed or not on PATH. No stack was started.'
}
docker version | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Runtime blocker: Docker CLI exists but the Docker engine is unavailable.' }

python scripts/validate_static.py
$runId = 'ARGUS-' + (Get-Date).ToUniversalTime().ToString('yyyyMMdd') + '-LOCAL-R' + $RunNumber.ToString('00')
$evidence = Join-Path $root 'evidence'
$runDir = Join-Path $evidence $runId
if (Test-Path -LiteralPath $runDir) { throw "Refusing to overwrite or append any existing evidence for $runId. Choose a different -RunNumber." }
New-Item -ItemType Directory -Path $runDir | Out-Null
$manifest = [ordered]@{ manifest_version='argus.d0a-local-run/v1'; run_id=$runId; scenario='D0A-LOCAL'; approval_state='approved'; concurrency=1; minimum_interval_seconds=1 }
Write-Utf8NoBom (Join-Path $runDir 'run-manifest.json') ($manifest | ConvertTo-Json -Compress)

# This runner is deliberately sequential: concurrency is fixed at one and every request is separated by >= 1 second.
try {
    Invoke-Native { docker compose down --volumes --remove-orphans }
    if ($LASTEXITCODE -ne 0) { throw "Compose cleanup before startup failed with exit code $LASTEXITCODE." }
    Invoke-Native { docker compose up --build --detach }
    if ($LASTEXITCODE -ne 0) { throw "Compose startup failed with exit code $LASTEXITCODE." }
    $gatewayPort = Invoke-Native { docker compose port gateway 8080 }
    $gatewayPortExit = $LASTEXITCODE
    $gatewayPortText = ($gatewayPort | Out-String).Trim()
    Write-Utf8NoBom (Join-Path $runDir 'gateway-published-port.txt') $gatewayPortText
    if ($gatewayPortExit -ne 0 -or $gatewayPortText -notmatch '(^|\s)127\.0\.0\.1:18080\s*$') {
        throw "Gateway published-port assertion failed; expected 127.0.0.1:18080, observed '$gatewayPortText'."
    }
    $provenance = [ordered]@{
        run_id = $runId
        fixture_sha256 = (Get-FileHash fixtures/d0a-local-fixtures.json -Algorithm SHA256).Hash.ToLowerInvariant()
        seed_sha256 = (Get-FileHash mysql/init.sql -Algorithm SHA256).Hash.ToLowerInvariant()
        event_schema_sha256 = (Get-FileHash schemas/event-v1.json -Algorithm SHA256).Hash.ToLowerInvariant()
        hybridnb_schema_sha256 = (Get-FileHash schemas/hybridnb-request-envelope-v1.json -Algorithm SHA256).Hash.ToLowerInvariant()
        compose_images = (Invoke-Native { docker compose images --format json } | Out-String).Trim()
    }
    Write-Utf8NoBom (Join-Path $runDir 'provenance.json') ($provenance | ConvertTo-Json -Depth 3)
    $deadline = (Get-Date).AddSeconds(90)
    $health = $null
    $lastHealthError = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $candidate = Invoke-WebRequest -Uri 'http://127.0.0.1:18080/health' -UseBasicParsing -ErrorAction Stop
            if ($candidate.StatusCode -eq 200) { $health = $candidate; break }
            $lastHealthError = "unexpected HTTP status: $($candidate.StatusCode)"
        }
        catch {
            $lastHealthError = $_.Exception.Message
        }
        Start-Sleep -Seconds 2
    }
    if ($null -eq $health -or $health.StatusCode -ne 200) {
        Write-Utf8NoBom (Join-Path $runDir 'gateway-health-last-error.txt') ([string]$lastHealthError)
        throw 'Gateway health check did not become ready within 90 seconds.'
    }
    $last = [DateTime]::MinValue
    function Invoke-D0Post($Path, $Body, $Headers) {
        $wait = 1 - ((Get-Date) - $last).TotalSeconds; if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
        $script:last = Get-Date
        try { $r = Invoke-WebRequest -Uri ('http://127.0.0.1:18080' + $Path) -Method Post -ContentType 'application/json' -Body ($Body | ConvertTo-Json -Compress) -Headers $Headers -UseBasicParsing; return @{ Status=$r.StatusCode; Body=($r.Content | ConvertFrom-Json) } }
        catch { return @{ Status=[int]$_.Exception.Response.StatusCode; Body=$null } }
    }
    $base = @{ 'X-ARGUS-Run-Id'=$runId; 'X-ARGUS-Request-Id'=($runId + '-AUTH') }
    $auth = Invoke-D0Post '/auth' @{run_id=$runId;fixture_id='ATK-S02-SYNTH-AUTH-01';probe='fixture-token-v1'} $base
    if ($auth.Status -ne 200) { throw "S02 failed: HTTP $($auth.Status)" }
    $markerHeaders = @{ 'X-ARGUS-Run-Id'=$runId; 'X-ARGUS-Request-Id'=($runId + '-MARK'); 'X-ARGUS-Session'=$auth.Body.session_token }
    $marker = Invoke-D0Post '/admin/marker' @{run_id=$runId;fixture_id='ATK-S04-MARKER-01';action='write_fixed_marker';upload_ticket_id=$auth.Body.upload_ticket_id} $markerHeaders
    if ($marker.Status -ne 200) { throw "S04 failed: HTTP $($marker.Status)" }
    $bad = Invoke-D0Post '/auth' @{run_id='not-a-run';fixture_id='ATK-S02-SYNTH-AUTH-01';probe='fixture-token-v1'} @{ 'X-ARGUS-Run-Id'='not-a-run'; 'X-ARGUS-Request-Id'=($runId + '-BAD') }
    if ($bad.Status -ne 400) { throw "invalid run_id was not rejected: HTTP $($bad.Status)" }
    $unauth = Invoke-D0Post '/admin/marker' @{run_id=$runId;fixture_id='ATK-S04-MARKER-01';action='write_fixed_marker';upload_ticket_id='missing'} @{ 'X-ARGUS-Run-Id'=$runId; 'X-ARGUS-Request-Id'=($runId + '-NOAUTH') }
    if ($unauth.Status -ne 401) { throw "unauthenticated marker was not rejected: HTTP $($unauth.Status)" }
    Invoke-Native { python scripts/validate_evidence.py --evidence-root evidence --run-id $runId }
    if ($LASTEXITCODE -ne 0) { throw "Evidence validation failed with exit code $LASTEXITCODE." }
    Write-Host "D0A scenario passed: $runId"
}
catch {
    $failure = [ordered]@{
        run_id = $runId
        failure_time_utc = (Get-Date).ToUniversalTime().ToString('o')
        error = $_.Exception.Message
    }
    Write-Utf8NoBom (Join-Path $runDir 'failure.json') ($failure | ConvertTo-Json)
    Write-Utf8NoBom (Join-Path $runDir 'compose-ps.txt') (Invoke-Native { docker compose ps --format json } | Out-String)
    Write-Utf8NoBom (Join-Path $runDir 'compose-logs.txt') (Invoke-Native { docker compose logs --no-color --timestamps gateway web was db } | Out-String)
    throw
}
finally {
    Invoke-Native { docker compose down --volumes --remove-orphans }
}
