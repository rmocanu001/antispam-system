<#
.SYNOPSIS
    Descarcă corpusul public SpamAssassin pentru testare (port Windows al download_corpus.sh).
.DESCRIPTION
    Descarcă arhivele easy_ham / hard_ham / spam, le dezarhivează cu tar (inclus în Windows 10+),
    redenumește fișierele în .eml și le distribuie în testdata/corpus/ham și testdata/corpus/spam.
    Idempotent: sare peste arhivele și fișierele deja prezente.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/Download-Corpus.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir  = Split-Path -Parent $ScriptDir
$CorpusDir   = Join-Path $ProjectDir 'testdata\corpus'
$DownloadDir = Join-Path $CorpusDir 'downloads'
$HamDir      = Join-Path $CorpusDir 'ham'
$SpamDir     = Join-Path $CorpusDir 'spam'
$BaseUrl     = 'https://spamassassin.apache.org/old/publiccorpus'

$Archives = @(
    '20030228_easy_ham.tar.bz2',
    '20030228_easy_ham_2.tar.bz2',
    '20030228_hard_ham.tar.bz2',
    '20030228_spam.tar.bz2',
    '20030228_spam_2.tar.bz2'
)

Write-Host '=== SpamAssassin Corpus Downloader ===' -ForegroundColor Cyan
Write-Host "Director țintă: $CorpusDir"

foreach ($d in @($DownloadDir, $HamDir, $SpamDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
}

# --- Descărcare ---
foreach ($archive in $Archives) {
    $dest = Join-Path $DownloadDir $archive
    if (Test-Path $dest) {
        Write-Host "Deja descărcat: $archive"
        continue
    }
    Write-Host "Descarc: $archive ..."
    try {
        Invoke-WebRequest -Uri "$BaseUrl/$archive" -OutFile $dest -UseBasicParsing
    } catch {
        Write-Warning "Nu am putut descărca $archive : $_"
    }
}

# --- Dezarhivare + redenumire în .eml ---
Write-Host ''
Write-Host 'Dezarhivez și convertesc...'

foreach ($archive in $Archives) {
    $src = Join-Path $DownloadDir $archive
    if (-not (Test-Path $src)) {
        Write-Warning "Arhivă lipsă, o sar: $archive"
        continue
    }

    if ($archive -like '*spam*') {
        $targetDir = $SpamDir; $prefix = 'spam'
    } else {
        $targetDir = $HamDir; $prefix = 'ham'
    }

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null

    Write-Host "Dezarhivez $archive ..."
    & tar -xjf $src -C $tmp 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Dezarhivarea a eșuat pentru $archive (tar exit $LASTEXITCODE)"
        Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        continue
    }

    Get-ChildItem -Path $tmp -Recurse -File |
        Where-Object { $_.Name -ne 'cmds' -and $_.Extension -ne '.bz2' } |
        ForEach-Object {
            $targetFile = Join-Path $targetDir ("{0}_{1}.eml" -f $prefix, $_.Name)
            if (-not (Test-Path $targetFile)) {
                Copy-Item -Path $_.FullName -Destination $targetFile
            }
        }

    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
    Write-Host "  -> extras în $targetDir"
}

# --- Numărătoare ---
$hamCount  = (Get-ChildItem -Path $HamDir  -Filter *.eml -File -ErrorAction SilentlyContinue | Measure-Object).Count
$spamCount = (Get-ChildItem -Path $SpamDir -Filter *.eml -File -ErrorAction SilentlyContinue | Measure-Object).Count

Write-Host ''
Write-Host '=== Corpus gata ===' -ForegroundColor Green
Write-Host "Ham:   $hamCount  ($HamDir)"
Write-Host "Spam:  $spamCount ($SpamDir)"
Write-Host "Total: $($hamCount + $spamCount)"
Write-Host ''
Write-Host 'Rulează comparația cu:'
Write-Host '  scripts\Run-LlmComparison.ps1 -Limit 100'
