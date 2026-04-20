# ============================================================
# Instaleaza certificatul IGSU Root CA in Windows
# Ruleaza ca Administrator in PowerShell:
#   Set-ExecutionPolicy RemoteSigned -Scope Process
#   .\scripts\Install-IgsuCA.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$tempCert = "$env:TEMP\igsu-ca.crt"

# --- Check admin privileges ---
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Acest script necesita drepturi de Administrator. Ruleaza PowerShell ca Admin."
    exit 1
}

# --- Find the correct Docker volume (docker-compose prefixes with project name) ---
Write-Host "[1/4] Detectez volumul Docker cu certificate..." -ForegroundColor Cyan
$volumes = docker volume ls -q 2>$null | Where-Object { $_ -match "certs_data" }
if (-not $volumes) {
    Write-Error "Nu s-a gasit volumul Docker *certs_data*. Ruleaza mai intai: docker-compose up cert-init"
    exit 1
}
# Pick the last match (most likely the project-prefixed one with actual data)
$certVolume = ($volumes | Select-Object -Last 1).Trim()
Write-Host "  Volum gasit: $certVolume" -ForegroundColor Green

# --- Extract CA cert ---
Write-Host "[2/4] Extrag certificatul CA din Docker volume..." -ForegroundColor Cyan
docker run --rm -v "${certVolume}:/certs" alpine:3.19 cat /certs/ca.crt | Out-File -Encoding ASCII $tempCert

if (-not (Test-Path $tempCert) -or (Get-Item $tempCert).Length -eq 0) {
    Write-Error "Nu s-a putut extrage ca.crt. Verifica ca certificatele au fost generate: docker-compose up cert-init"
    exit 1
}

# --- Install into Windows Root CA Store ---
Write-Host "[3/4] Instalez in Windows Root CA Store..." -ForegroundColor Cyan
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($tempCert)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store.Add($cert)
$store.Close()

Remove-Item $tempCert -Force

# --- DNS setup ---
Write-Host "[4/4] Configurez DNS local (hosts file)..." -ForegroundColor Cyan
$dnsScript = Join-Path $PSScriptRoot "setup-dns.ps1"
& $dnsScript

Write-Host ""
Write-Host "Gata! IGSU Root CA instalat." -ForegroundColor Green
Write-Host "Reporneste browserul pentru ca certificatul sa fie recunoscut." -ForegroundColor Yellow
