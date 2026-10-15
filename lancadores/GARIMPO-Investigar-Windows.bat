@echo off
chcp 65001 >nul
title GARIMPO - Investigar (DEIVOSINT)
cd /d "%~dp0.."
where python >nul 2>nul && (set PY=python) || (set PY=python3)
set /p ALVO="Digite o alvo (dominio, IP, e-mail, username, CNPJ, URL): "
%PY% garimpo.py investigar "%ALVO%"
echo.
echo Abra o arquivo dossie.html indicado acima.
pause
