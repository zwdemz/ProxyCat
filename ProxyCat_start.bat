@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo 正在启动 ProxyCat 终端模式...
echo 提示：终端模式与 Web 模式使用同一代理端口，请勿同时启动 app.py。

where py >nul 2>&1
if errorlevel 1 (
    python ProxyCat.py
) else (
    py -3 ProxyCat.py
)

if errorlevel 1 (
    echo.
    echo ProxyCat 启动失败，请查看上方错误信息。
    pause
)
