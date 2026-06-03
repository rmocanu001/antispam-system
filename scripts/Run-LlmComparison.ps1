<#
.SYNOPSIS
    Rulează comparația LLM (cmd/llmcompare) folosind Ollama din Docker Desktop.
.DESCRIPTION
    Flux complet, totul prin Docker Desktop:
      1. pornește containerul `ollama` din docker-compose (dacă nu rulează);
      2. așteaptă să fie gata;
      3. face `docker exec ollama ollama pull <model>` pentru fiecare model;
      4. rulează `go run ./cmd/llmcompare` de pe host către endpoint-ul expus (localhost:11434).

    Modul "isolated" necesită doar Ollama. Modul "ensemble" folosește și SpamAssassin/ClamAV;
    pornește-le cu `docker compose up -d spamassassin clamav` sau întreaga stivă cu
    `docker compose up -d`. Dacă lipsesc, pipeline-ul le sare grațios.
.PARAMETER Models
    Listă de modele separate prin virgulă. Default: qwen2.5:7b,llama3.1:8b,mistral:7b
.PARAMETER Mode
    both | isolated | ensemble (default both)
.PARAMETER Limit
    Emailuri per categorie (default 200, 0 = toate)
.PARAMETER BaseUrl
    Endpoint-ul LLM expus de Docker pe host. Default: http://localhost:11434/v1
.PARAMETER OllamaContainer
    Numele containerului Ollama. Default: ollama
.PARAMETER SkipPull
    Sare peste `ollama pull` (modelele sunt deja în volum).
.PARAMETER NoStart
    Nu porni automat containerul (presupune că rulează deja).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/Run-LlmComparison.ps1 -Limit 100
.EXAMPLE
    .\scripts\Run-LlmComparison.ps1 -Models "qwen2.5:7b,llama3.1:8b" -Mode isolated
#>
[CmdletBinding()]
param(
    [string]$Models = 'qwen2.5:7b,llama3.1:8b,mistral:7b',
    [ValidateSet('both', 'isolated', 'ensemble')]
    [string]$Mode = 'both',
    [int]$Limit = 200,
    [string]$BaseUrl = 'http://localhost:11434/v1',
    [string]$OllamaContainer = 'ollama',
    [switch]$SkipPull,
    [switch]$NoStart
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker nu este pe PATH. Pornește Docker Desktop și încearcă din nou.'
}

function Test-OllamaReady {
    param([string]$Container)
    & docker exec $Container ollama list 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}

# --- 1. Pornește containerul ollama (dacă e cazul) ---
if (-not $NoStart) {
    $running = (& docker ps --filter "name=^/$OllamaContainer$" --format '{{.Names}}' | Select-Object -First 1)
    if (-not $running) {
        Write-Host "Pornesc containerul '$OllamaContainer' din docker-compose..." -ForegroundColor Cyan
        & docker compose up -d $OllamaContainer
        if ($LASTEXITCODE -ne 0) { throw "docker compose up -d $OllamaContainer a eșuat." }
    } else {
        Write-Host "Containerul '$OllamaContainer' rulează deja." -ForegroundColor DarkGray
    }

    # --- 2. Așteaptă să fie gata (max ~90s) ---
    Write-Host 'Aștept ca Ollama să fie gata...' -NoNewline
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-OllamaReady -Container $OllamaContainer) { $ready = $true; break }
        Start-Sleep -Seconds 3
        Write-Host '.' -NoNewline
    }
    Write-Host ''
    if (-not $ready) { throw "Ollama nu a devenit disponibil în containerul '$OllamaContainer'." }
}

# --- 3. Pull modele în container ---
$modelArray = $Models.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if (-not $SkipPull) {
    foreach ($m in $modelArray) {
        Write-Host "Pull model: $m" -ForegroundColor Cyan
        & docker exec $OllamaContainer ollama pull $m
        if ($LASTEXITCODE -ne 0) { Write-Warning "Pull eșuat pentru $m (continui)." }
    }
}

# --- 4. Rulează comparația de pe host către endpoint-ul expus ---
$goArgs = @(
    'run', './cmd/llmcompare',
    '--models', $Models,
    '--mode', $Mode,
    '--limit', $Limit,
    '--base-url', $BaseUrl
)

Write-Host ''
Write-Host "go $($goArgs -join ' ')" -ForegroundColor DarkGray
& go @goArgs
exit $LASTEXITCODE
