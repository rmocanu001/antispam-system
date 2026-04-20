@echo off
:: ============================================================
:: Configureaza inregistrarile DNS locale (hosts file) pentru
:: stack-ul IGSU Anti-Spam Mail.
::
:: Ruleaza ca Administrator!
:: ============================================================

set HOSTS=%SystemRoot%\System32\drivers\etc\hosts
set MARKER=# IGSU Anti-Spam Mail Stack
set IP=127.0.0.1

:: Check admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo EROARE: Acest script necesita drepturi de Administrator.
    echo Click dreapta pe fisier ^> Run as administrator
    pause
    exit /b 1
)

echo.
echo === IGSU DNS Setup ===
echo.

:: Check and add each hostname
call :ADD_HOST mail.igsu.local
call :ADD_HOST admin.igsu.local

echo.
echo Verificare:
ping -n 1 -w 500 mail.igsu.local >nul 2>&1
if %errorlevel% equ 0 (
    echo   mail.igsu.local  -^> OK
) else (
    echo   mail.igsu.local  -^> reporneste terminalul pentru actualizare
)
ping -n 1 -w 500 admin.igsu.local >nul 2>&1
if %errorlevel% equ 0 (
    echo   admin.igsu.local -^> OK
) else (
    echo   admin.igsu.local -^> reporneste terminalul pentru actualizare
)

echo.
echo Servicii disponibile:
echo   https://mail.igsu.local        - Roundcube webmail
echo   https://admin.igsu.local:8443  - Admin conturi mail
echo.
pause
exit /b 0

:: ---- Subroutine: add hostname if missing ----
:ADD_HOST
set HOSTNAME=%~1
findstr /i /c:"%HOSTNAME%" "%HOSTS%" >nul 2>&1
if %errorlevel% equ 0 (
    echo   Deja exista: %HOSTNAME%
) else (
    echo %IP%	%HOSTNAME%>>"%HOSTS%"
    echo   Adaugat:     %IP%	%HOSTNAME%
)
exit /b 0
