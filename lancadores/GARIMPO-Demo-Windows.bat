@echo off
chcp 65001 >nul
title GARIMPO - Demonstracao (DEIVOSINT)
cd /d "%~dp0.."
set PYTHONUTF8=1
where python >nul 2>nul && (set PY=python) || (set PY=python3)
%PY% garimpo.py demo
if exist "casos\demo\dossie.html" start "" "casos\demo\dossie.html"
echo.
echo Pronto! O dossie de demonstracao abriu no navegador.
pause
