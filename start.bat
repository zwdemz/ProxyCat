@echo off
chcp 65001 >nul
setlocal
title ProxyCat
cd /d "%~dp0"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo 正在启动 ProxyCat Web 控制面板和代理服务...
echo app.py 已包含代理服务，请勿同时启动 ProxyCat.py。

python app.py
set "PROXYCAT_EXIT_CODE=%ERRORLEVEL%"
if not "%PROXYCAT_EXIT_CODE%"=="0" (
    echo.
    echo ProxyCat 启动失败，请查看上方错误信息。
    pause
)
exit /b %PROXYCAT_EXIT_CODE%
