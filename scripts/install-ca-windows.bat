@echo off
:: ============================================================
:: Instaleaza certificatul IGSU Root CA in Windows Certificate Store
:: si configureaza DNS local (hosts file).
:: Ruleaza ca Administrator!
:: ============================================================

set SCRIPT_DIR=%~dp0
set CA_EXPORT=%SCRIPT_DIR%igsu-ca-temp.crt

:: Check admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo EROARE: Acest script necesita drepturi de Administrator.
    echo Click dreapta pe fisier ^> Run as administrator
    pause
    exit /b 1
)

echo.
echo [1/4] Detectez volumul Docker cu certificate...

:: Find the correct volume name (docker-compose prefixes with project name)
set CERT_VOLUME=
for /f "tokens=2" %%V in ('docker volume ls --format "{{.Name}}" ^| findstr /i "certs_data"') do (
    set CERT_VOLUME=%%V
)
:: Fallback: try without for/f parsing
if "%CERT_VOLUME%"=="" (
    for /f %%V in ('docker volume ls -q ^| findstr /i "certs_data"') do (
        set CERT_VOLUME=%%V
    )
)
if "%CERT_VOLUME%"=="" (
    echo EROARE: Nu s-a gasit volumul Docker *certs_data*.
    echo Asigura-te ca ai rulat: docker-compose up cert-init
    pause
    exit /b 1
)

echo   Volum gasit: %CERT_VOLUME%

echo [2/4] Extrag certificatul CA din Docker volume...
docker run --rm -v %CERT_VOLUME%:/certs alpine:3.19 cat /certs/ca.crt > "%CA_EXPORT%" 2>nul

if not exist "%CA_EXPORT%" (
    echo EROARE: Nu s-a putut extrage ca.crt din volumul Docker.
    echo Asigura-te ca ai rulat: docker-compose up cert-init
    pause & exit /b 1
)

:: Verify file is not empty
for %%A in ("%CA_EXPORT%") do if %%~zA==0 (
    echo EROARE: Fisierul ca.crt extras este gol.
    echo Asigura-te ca certificatele au fost generate: docker-compose up cert-init
    del "%CA_EXPORT%" 2>nul
    pause & exit /b 1
)

echo [3/4] Instalez in Windows Root CA Store...
certutil -addstore -f "ROOT" "%CA_EXPORT%"

if %errorlevel% neq 0 (
    echo EROARE: Instalare esuata. Ruleaza ca Administrator!
    del "%CA_EXPORT%" 2>nul
    pause & exit /b 1
)

del "%CA_EXPORT%" 2>nul

echo.
echo OK! Certificatul IGSU Root CA a fost instalat.
echo.

:: Configureaza DNS (hosts file) automat
echo [4/4] Configurez DNS local (hosts file)...
call "%SCRIPT_DIR%setup-dns.bat"
