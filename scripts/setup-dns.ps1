# ============================================================
# Configureaza inregistrarile DNS locale (hosts file) pentru
# stack-ul IGSU Anti-Spam Mail.
#
# Ruleaza ca Administrator in PowerShell:
#   Set-ExecutionPolicy RemoteSigned -Scope Process
#   .\scripts\setup-dns.ps1
#
# Optiuni:
#   -Remove    Sterge inregistrarile in loc sa le adauge
#   -IP <addr> Foloseste alt IP decat 127.0.0.1
# ============================================================

param(
    [switch]$Remove,
    [string]$IP = "127.0.0.1"
)

$ErrorActionPreference = "Stop"

$hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$marker    = "# IGSU Anti-Spam Mail Stack"

$hostnames = @(
    "mail.igsu.local",
    "admin.igsu.local"
)

# --- Check admin privileges ---
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Acest script necesita drepturi de Administrator. Ruleaza PowerShell ca Admin."
    exit 1
}

# --- Read current hosts file ---
$lines = Get-Content $hostsPath

if ($Remove) {
    Write-Host "Sterg inregistrarile IGSU din hosts..." -ForegroundColor Yellow
    $filtered = $lines | Where-Object {
        $line = $_.Trim()
        $dominated = $false
        foreach ($h in $hostnames) {
            if ($line -match "\s+$([regex]::Escape($h))\s*$" -or $line -match "\s+$([regex]::Escape($h))$") {
                $dominated = $true
                break
            }
        }
        if ($line -eq $marker) { $dominated = $true }
        -not $dominated
    }
    Set-Content -Path $hostsPath -Value $filtered -Encoding ASCII
    Write-Host "Inregistrarile IGSU au fost sterse." -ForegroundColor Green
    exit 0
}

# --- Add mode ---
Write-Host ""
Write-Host "=== IGSU DNS Setup ===" -ForegroundColor Cyan
Write-Host ""

$hostsRaw = Get-Content $hostsPath -Raw
$added    = 0
$skipped  = 0

# Add marker if not present
if ($hostsRaw -notmatch [regex]::Escape($marker)) {
    Add-Content $hostsPath "`n$marker"
}

foreach ($h in $hostnames) {
    if ($hostsRaw -match "(?m)^\s*[\d.:]+\s+.*$([regex]::Escape($h))") {
        Write-Host "  Deja exista: $h" -ForegroundColor Yellow
        $skipped++
    } else {
        $entry = "$IP`t$h"
        Add-Content $hostsPath $entry
        Write-Host "  Adaugat:     $IP`t$h" -ForegroundColor Green
        $added++
    }
}

Write-Host ""
Write-Host "Rezultat: $added adaugate, $skipped existente." -ForegroundColor Cyan
Write-Host ""
Write-Host "Verificare:" -ForegroundColor White

foreach ($h in $hostnames) {
    try {
        $resolved = [System.Net.Dns]::GetHostAddresses($h) | Select-Object -First 1
        Write-Host "  $h -> $($resolved.IPAddressToString)" -ForegroundColor Green
    } catch {
        Write-Host "  $h -> nu se poate rezolva (reporneste terminalul)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Servicii disponibile:" -ForegroundColor White
Write-Host "  https://mail.igsu.local        - Roundcube webmail" -ForegroundColor White
Write-Host "  https://admin.igsu.local:8443   - Admin conturi mail" -ForegroundColor White
Write-Host ""
