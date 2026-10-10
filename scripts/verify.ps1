# Verify AI Workstation Defence yourself, on Windows (PowerShell).
#
#   powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
#
# Builds from source, runs every test, replays a sample session and checks
# the log. Run from an Administrator PowerShell to also run the tool with
# its outbound network access blocked by Windows Firewall.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Pass($m) { Write-Host "  PASS  $m" -ForegroundColor Green }
function Skip($m) { Write-Host "  SKIP  $m" -ForegroundColor Yellow }
function Step($m) { Write-Host "`n== $m" }
function Check() { if ($LASTEXITCODE -ne 0) { throw "command failed with exit code $LASTEXITCODE" } }

Step "1. Build from source (exact dependency versions from Cargo.lock)"
cargo build --release --locked; Check
$awd = Join-Path (Get-Location) "target\release\awd.exe"
Pass "built $awd"

Step "2. Run every test (unit, end-to-end, trust)"
cargo test --locked --workspace; Check
Pass "all tests passed"

$work = Join-Path ([IO.Path]::GetTempPath()) ("awd-verify-" + [Guid]::NewGuid())
New-Item -ItemType Directory $work | Out-Null
try {
    Step "3. Replay the sample session and read the report"
    & $awd watch --source replay --input examples\sample-session.jsonl --data-dir "$work\data" --home /Users/ana | Out-Null; Check
    & $awd report --data-dir "$work\data" --home /Users/ana; Check
    Pass "report produced"

    Step "4. Check the log, then tamper with it"
    & $awd verify --data-dir "$work\data"; Check
    Copy-Item -Recurse "$work\data" "$work\cut"
    Get-Content "$work\data\activity.log" -TotalCount 5 | Set-Content "$work\cut\activity.log"
    & $awd verify --data-dir "$work\cut"
    if ($LASTEXITCODE -ne 2) { throw "cutting off the newest entries was NOT detected" }
    Pass "cutting off the newest entries was detected"
    $log = "$work\data\activity.log"
    (Get-Content $log -Raw).Replace("cart.ts", "cart.js") | Set-Content $log -NoNewline
    & $awd verify --data-dir "$work\data"
    if ($LASTEXITCODE -ne 2) { throw "tampering was NOT detected" }
    Pass "a one-character edit was detected"

    Step "5. Run with outbound network blocked"
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($admin) {
        $rule = "awd-verify-no-network"
        New-NetFirewallRule -DisplayName $rule -Direction Outbound -Program $awd -Action Block | Out-Null
        try {
            & $awd watch --source replay --input examples\sample-session.jsonl --data-dir "$work\net" --home /Users/ana | Out-Null; Check
            & $awd report --data-dir "$work\net" --home /Users/ana | Out-Null; Check
            & $awd verify --data-dir "$work\net" | Out-Null; Check
            Pass "the replayed session ran with Windows Firewall blocking all its outbound traffic"
        } finally {
            Remove-NetFirewallRule -DisplayName $rule
        }
    } else {
        Skip "run as Administrator to test with outbound traffic blocked"
    }
} finally {
    Remove-Item -Recurse -Force $work
}

Step "Done"
Write-Host "  Every check above ran on your machine, from source you can read."
Write-Host "  They cover a replayed session. Live capture is not exercised here: see docs\TESTING.md."
