# run_demo.ps1 - the short demo, fully automatic. Nothing to prepare by hand.
#
#   ./run_demo.ps1
#
#   0 - 20 s   normal traffic: 6 users browse the victim, the detector learns what normal looks like
#   20 - 40 s  20 bots flood the victim, the detector raises the alarm and blocks them
#   40 - 60 s  the users carry on, the victim is back to normal
#
# While it runs, open http://localhost:8080 to see the victim's page.
# At the end the results are saved to output/runs/demo_<date> and summarised with a chart.
#
# The same thing without this script (from sources/docker):  docker compose up -d --build
# For the long scenarios (60 s baseline + 120 s attack, UDP, flash crowd) use run_lab.ps1.
param(
    [int]$Bots = 20,
    [int]$Clients = 6,
    [switch]$NoAnalyze
)

$ErrorActionPreference = "Continue"   # docker writes progress to stderr
Set-Location $PSScriptRoot
# docker-compose.yml + the demo settings next to it (separator on Windows is ";")
$env:COMPOSE_FILE = "sources/docker/docker-compose.yml;sources/docker/docker-compose.override.yml"
$env:BOTS = "$Bots"
$env:CLIENTS = "$Clients"

Write-Host "=== Demo: 20 s normal, then 20 s attack by $Bots bots, $Clients legitimate users ==="

Write-Host "--- stopping any previous run"
docker compose --profile syn --profile view down --remove-orphans 2>&1 | Out-Null

Write-Host "--- building and starting everything (the first build takes a few minutes)"
docker compose up -d --build 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { docker compose up -d --build; throw "docker compose up failed" }

$t0 = [int](Get-Content output/results/t0).Trim()
$now = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
Write-Host "--- everything is starting. The demo begins in about $([Math]::Max(0, $t0 - $now)) s."
Write-Host "--- open http://localhost:8080 now to watch the victim's page (it slows down for a few seconds at the 20 s mark)"
Write-Host "--- detector log (ends by itself after about 60 s):"
docker compose logs -f --no-log-prefix detector

Start-Sleep -Seconds 3
docker compose logs --no-color detector 2>&1 | Out-File -Encoding utf8 output/results/detector.log
docker compose logs --no-color client 2>&1 | Out-File -Encoding utf8 output/results/client.log
docker compose --profile syn --profile view down --remove-orphans 2>&1 | Out-Null

$runDir = "output/runs/demo_$(Get-Date -Format 'yyyyMMdd-HHmmss')"
New-Item -ItemType Directory -Force $runDir | Out-Null
Copy-Item output/results/* $runDir -Recurse -Force -Exclude ".gitkeep"
Write-Host "--- saved to $runDir"

if (-not $NoAnalyze) {
    python output/analyze_results.py $runDir --attack http
}
