@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo 正在启动 ProxyCat Web 控制面板和代理服务...
echo 提示：app.py 已包含代理服务，请勿同时启动 ProxyCat.py。

where py >nul 2>&1
if errorlevel 1 (
    python app.py
) else (
    py -3 app.py
)

if errorlevel 1 (
    echo.
    echo ProxyCat 启动失败，请查看上方错误信息。
    pause
)
