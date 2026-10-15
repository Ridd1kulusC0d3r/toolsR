@echo off
chcp 65001 >nul
title GARIMPO - Investigar (DEIVOSINT)
cd /d "%~dp0.."
set PYTHONUTF8=1
where python >nul 2>nul && (set PY=python) || (set PY=python3)
set /p ALVO="Digite o alvo (dominio, IP, e-mail, username, CNPJ, URL, telefone): "
%PY% garimpo.py investigar "%ALVO%" > "%TEMP%\garimpo_saida.txt"
type "%TEMP%\garimpo_saida.txt"
for /f "tokens=2* delims= " %%a in ('findstr /b /c:"✔ Dossiê:" "%TEMP%\garimpo_saida.txt"') do start "" "%%b"
echo.
pause
