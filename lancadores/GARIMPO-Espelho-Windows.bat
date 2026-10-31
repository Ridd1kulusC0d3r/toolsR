@echo off
chcp 65001 >nul
title GARIMPO - ESPELHO (auto-auditoria OPSEC)
cd /d "%~dp0.."
set PYTHONUTF8=1
where python >nul 2>nul && (set PY=python) || (set PY=python3)
echo ESPELHO: o que um observador passivo ve do SEU dominio. Rode so no seu ativo.
set /p ALVO="Digite o SEU dominio/marca: "
%PY% garimpo.py espelho "%ALVO%" > "%TEMP%\garimpo_esp.txt"
type "%TEMP%\garimpo_esp.txt"
for /f "tokens=2* delims= " %%a in ('findstr /b /c:"✔ Relatório ESPELHO:" "%TEMP%\garimpo_esp.txt"') do start "" "%%b"
echo.
pause
