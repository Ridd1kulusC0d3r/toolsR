@echo off
chcp 65001 >nul
title GARIMPO - Painel (DEIVOSINT)
cd /d "%~dp0.."
set PYTHONUTF8=1
where python >nul 2>nul && (set PY=python) || (set PY=python3)
echo O painel vai abrir no navegador. Para encerrar, feche esta janela.
%PY% garimpo.py painel
pause
