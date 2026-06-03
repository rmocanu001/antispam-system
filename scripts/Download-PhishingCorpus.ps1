<#
.SYNOPSIS
    Descarcă un corpus MODERN de phishing (Jose Nazario Phishing Corpus) și îl sparge în .eml.
.DESCRIPTION
    Descarcă fișierele mbox phishing-<an> de la monkey.org, separă fiecare mbox în mesaje
    individuale .eml și le pune în testdata/corpus/phishing/. Implicit ia anii 2023-2025
    (phishing real, recent). Idempotent: sare peste arhivele deja descărcate.

    Formatul mbox: mesajele sunt separate de linii care încep cu "From <expeditor> <zi> <lună> ...".
    Linia separator "From " NU face parte din mesajul RFC 822 și este eliminată la scriere.

    Citirea/scrierea se face cu ISO-8859-1 (byte-preserving) ca să nu corupem octeții non-UTF8;
    parserul MIME (enmime) interpretează charset-ul real din anteturi.
.PARAMETER Years
    Anii de descărcat. Default: 2023,2024,2025
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/Download-PhishingCorpus.ps1
.EXAMPLE
    .\scripts\Download-PhishingCorpus.ps1 -Years 2024,2025
#>
[CmdletBinding()]
param(
    [int[]]$Years = @(2023, 2024, 2025)
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir   = Split-Path -Parent $ScriptDir
$CorpusDir    = Join-Path $ProjectDir 'testdata\corpus'
$DownloadDir  = Join-Path $CorpusDir 'downloads'
$PhishingDir  = Join-Path $CorpusDir 'phishing'
$BaseUrl      = 'https://monkey.org/~jose/phishing'

Write-Host '=== Phishing Corpus Downloader (Nazario) ===' -ForegroundColor Cyan
Write-Host "Ani: $($Years -join ', ')"
Write-Host "Director țintă: $PhishingDir"

foreach ($d in @($DownloadDir, $PhishingDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
}

$latin1 = [System.Text.Encoding]::GetEncoding('iso-8859-1')
# Granița de mesaj: linie care începe cu "From " urmat de expeditor și o zi a săptămânii.
$boundary = [regex]'(?m)^From \S+ (?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) '

$totalWritten = 0

foreach ($year in $Years) {
    $name = "phishing-$year"
    $dest = Join-Path $DownloadDir "$name.mbox"

    # --- Descărcare ---
    if (Test-Path $dest) {
        Write-Host "Deja descărcat: $name"
    } else {
        Write-Host "Descarc: $name ..."
        try {
            Invoke-WebRequest -Uri "$BaseUrl/$name" -OutFile $dest -UseBasicParsing
        } catch {
            Write-Warning "Nu am putut descărca $name : $_"
            continue
        }
    }

    # --- Spargere mbox -> .eml ---
    Write-Host "  Sparg $name în mesaje individuale..."
    $content = [System.IO.File]::ReadAllText($dest, $latin1)
    $matches  = $boundary.Matches($content)
    if ($matches.Count -eq 0) {
        Write-Warning "  Niciun mesaj detectat în $name (format neașteptat)"
        continue
    }

    $written = 0
    for ($i = 0; $i -lt $matches.Count; $i++) {
        $start = $matches[$i].Index
        $end   = if ($i + 1 -lt $matches.Count) { $matches[$i + 1].Index } else { $content.Length }
        $msg   = $content.Substring($start, $end - $start)

        # Elimină linia separator "From ..." (prima linie)
        $nl = $msg.IndexOf("`n")
        if ($nl -ge 0) { $msg = $msg.Substring($nl + 1) }
        $msg = $msg.TrimEnd("`r", "`n") + "`r`n"

        if ($msg.Length -lt 20) { continue } # sare peste fragmente goale

        $outFile = Join-Path $PhishingDir ("phish_{0}_{1:D5}.eml" -f $year, $i)
        if (-not (Test-Path $outFile)) {
            [System.IO.File]::WriteAllText($outFile, $msg, $latin1)
        }
        $written++
    }
    $totalWritten += $written
    Write-Host "  -> $written mesaje din $name"
}

$phishCount = (Get-ChildItem -Path $PhishingDir -Filter *.eml -File -ErrorAction SilentlyContinue | Measure-Object).Count

Write-Host ''
Write-Host '=== Corpus phishing gata ===' -ForegroundColor Green
Write-Host "Phishing .eml: $phishCount ($PhishingDir)"
Write-Host ''
Write-Host 'Comparația le include automat (flag implicit --phishing-dir testdata/corpus/phishing):'
Write-Host '  scripts\Run-LlmComparison.ps1 -Limit 200'
