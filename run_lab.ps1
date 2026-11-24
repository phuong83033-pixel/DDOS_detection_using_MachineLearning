# run_lab.ps1 - run one full lab scenario: baseline -> attack -> defense -> recovery.
#
#   ./run_lab.ps1 -Attack http            # 20 bots, real HTTP requests
#   ./run_lab.ps1 -Attack udp
#   ./run_lab.ps1 -Attack syn             # one machine, forged source addresses
#   ./run_lab.ps1 -Attack none            # baseline only: checks for false alarms
#   ./run_lab.ps1 -Attack flash           # flash crowd: legitimate users, 4x the requests
#   add -NoDefense for a detection-only run (nothing is blocked)
#
# Timeline defaults: 60 s baseline + 120 s attack + 40 s tail. Everything runs on an
# isolated Docker network (internal: true), nothing leaves your machine.
# Results go to output/results (current run) and output/runs (one folder per run).
param(
    [ValidateSet("http", "udp", "syn", "none", "flash")][string]$Attack = "http",
    [int]$Bots = 20,
    [int]$Clients = 6,
    [int]$Baseline = 60,
    [int]$AttackSeconds = 120,
    [int]$Tail = 40,
    [switch]$NoDefense,
    [switch]$Record,                       # save flow features as model training data (use with -NoDefense)
    [ValidateSet("auto", "ml", "entropy")][string]$Mode = "auto",   # detector mode
    [switch]$NoAnalyze,
    [switch]$View                          # also start the viewer: open http://localhost:8080 to see the victim's page
)

$ErrorActionPreference = "Continue"   # docker writes progress to stderr; exit codes are checked in Run
Set-Location $PSScriptRoot
$env:COMPOSE_FILE = "sources/docker/docker-compose.yml"   # every "docker compose" below uses this file

function Run([string]$what, [scriptblock]$cmd) {
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$what failed (exit code $LASTEXITCODE)" }
}

$total = $Baseline + $AttackSeconds + $Tail
$env:BASELINE = "$Baseline"
$env:ATTACK = "$AttackSeconds"
$env:TOTAL = "$total"
$env:DETECTOR_MODE = if ($Record) { "entropy" } else { $Mode }
$env:RECORD_FLOWS = if ($Record) { "1" } else { "0" }
$env:DEFENSE = if ($NoDefense) { "0" } else { "1" }
$env:FLASH_MULT = if ($Attack -eq "flash") { "4" } else { "1" }
$env:ATTACK_TYPE = if ($Attack -in @("http", "udp")) { $Attack } else { "http" }

Write-Host "=== Scenario: $Attack  bots=$Bots  clients=$Clients  timeline=${Baseline}s + ${AttackSeconds}s + ${Tail}s ==="

Write-Host "--- cleaning up the previous run"
Run "compose down" { docker compose --profile syn --profile view down --remove-orphans 2>&1 | Out-Null; $global:LASTEXITCODE = 0 }
Get-ChildItem output/results -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne ".gitkeep" } | Remove-Item -Recurse -Force
"ts,source,event,detail" | Out-File -Encoding ascii -NoNewline output/results/events.csv
Add-Content -Encoding ascii output/results/events.csv ""

Write-Host "--- building images"
Run "compose build" { docker compose --profile syn build --quiet }

Write-Host "--- starting the victim"
Run "victim up" { docker compose up -d --wait victim }

# One shared start time, taken from the Docker VM's clock, so every log lines up.
Run "write t0" { docker compose exec -T victim sh -c 'echo $(( $(date +%s) + 15 )) > /results/t0' }
$t0 = (Get-Content output/results/t0).Trim()
@{ attack = $Attack; baseline = $Baseline; attack_seconds = $AttackSeconds; total = $total; bots = $Bots; clients = $Clients; defense = (-not $NoDefense) } | ConvertTo-Json | Out-File -Encoding ascii output/results/timeline.json
Write-Host "--- T0 = $t0 (unix time), run lasts ${total}s"

$services = @("detector", "client")
$scale = @("--scale", "client=$Clients")
if ($Attack -in @("http", "udp")) { $services += "bot"; $scale += @("--scale", "bot=$Bots") }
$profile = @()
if ($Attack -eq "syn") { $services += "syn_attacker"; $profile = @("--profile", "syn") }
if ($View) { $services += "viewer"; $profile += @("--profile", "view") }

Run "services up" { docker compose @profile up -d @scale @services }
if ($View) { Write-Host "--- viewer is up: open http://localhost:8080 (the victim's page; it slows down during the attack)" }

$wait = $total + 30
Write-Host "--- running... waiting about ${wait}s (Ctrl+C to abort, then run: docker compose -f sources/docker/docker-compose.yml --profile syn down)"
Start-Sleep -Seconds $wait

Write-Host "--- collecting logs"
docker compose logs --no-color detector 2>&1 | Out-File -Encoding utf8 output/results/detector.log
docker compose logs --no-color client 2>&1 | Out-File -Encoding utf8 output/results/client.log
docker compose --profile syn --profile view down --remove-orphans 2>&1 | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runDir = "output/runs/${Attack}$(if ($NoDefense) { "-nodefense" })$(if ($Mode -ne "auto") { "-$Mode" })_$stamp"
New-Item -ItemType Directory -Force $runDir | Out-Null
Copy-Item output/results/* $runDir -Recurse -Force -Exclude ".gitkeep"
Write-Host "--- saved to $runDir"

if (-not $NoAnalyze) {
    python output/analyze_results.py $runDir --attack $Attack
}
