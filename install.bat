@echo off
:: ══════════════════════════════════════════════════════════════════
::  GuardClaw — One-command installer (Windows)
::  Usage: Double-click install.bat  or  run from PowerShell/CMD
:: ══════════════════════════════════════════════════════════════════
setlocal enabledelayedexpansion

echo.
echo  ========================================================
echo   GuardClaw v4.3.0 - Security Bouncer for AI Agents
echo   100%% local. No data leaves your machine.
echo  ========================================================
echo.

:: ── 1. Python check ──────────────────────────────────────────────
echo [1/5] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    python3 --version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python 3.9+ not found.
        echo         Download from: https://www.python.org/downloads/
        echo         Make sure to check "Add Python to PATH" during install.
        pause & exit /b 1
    )
    set PYTHON=python3
) else (
    set PYTHON=python
)
for /f "tokens=2" %%v in ('!PYTHON! --version 2^>^&1') do set PY_VER=%%v
echo [OK] Python !PY_VER!

:: ── 2. pip dependencies ──────────────────────────────────────────
echo.
echo [2/5] Installing Python dependencies...
!PYTHON! -m pip install -q customtkinter pyperclip requests
if errorlevel 1 (
    echo [ERROR] pip install failed.
    echo         Try: !PYTHON! -m pip install customtkinter pyperclip requests
    pause & exit /b 1
)
echo [OK] Core dependencies installed.

:: Optional httpx for async
!PYTHON! -m pip install -q httpx >nul 2>&1
if not errorlevel 1 (
    echo [OK] httpx (async support) installed.
) else (
    echo [WARN] httpx not installed. Async mode unavailable (optional).
)

:: ── 3. Ollama check ───────────────────────────────────────────────
echo.
echo [3/5] Checking Ollama...
ollama --version >nul 2>&1
if errorlevel 1 (
    echo [WARN] Ollama not found.
    echo        Download from: https://ollama.ai
    echo        Install it, then re-run this script OR run manually:
    echo          ollama serve
    echo          ollama pull qwen2.5-coder:1.5b
    echo.
    echo        Continuing without Ollama (static scanner will still work)...
) else (
    for /f "tokens=*" %%v in ('ollama --version 2^>^&1') do set OL_VER=%%v
    echo [OK] !OL_VER!

    :: ── 4. Pull default model ────────────────────────────────────
    echo.
    echo [4/5] Pulling default AI model (qwen2.5-coder:1.5b ~1 GB)...
    echo       For better accuracy: ollama pull qwen2.5-coder:7b
    echo.
    start /B ollama serve >nul 2>&1
    timeout /t 3 /nobreak >nul
    ollama pull qwen2.5-coder:1.5b
    if errorlevel 1 (
        echo [WARN] Model pull failed. Run manually: ollama pull qwen2.5-coder:1.5b
    ) else (
        echo [OK] Model ready.
    )
)

:: ── 5. Verify guardclaw.py ────────────────────────────────────────
echo.
echo [5/5] Verifying GuardClaw...
if not exist guardclaw.py (
    echo [ERROR] guardclaw.py not found in current directory.
    echo         Make sure you are running this from the GuardClaw folder.
    pause & exit /b 1
)
!PYTHON! -c "import ast; ast.parse(open('guardclaw.py').read())" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] guardclaw.py has a syntax error. Try re-downloading.
    pause & exit /b 1
)
echo [OK] guardclaw.py OK.

:: ── Optional: OpenClaw skill ──────────────────────────────────────
set OPENCLAW_SKILLS=%USERPROFILE%\.openclaw\workspace\skills
if exist "!OPENCLAW_SKILLS!" (
    if exist "SKILL.md" (
        mkdir "!OPENCLAW_SKILLS!\guardclaw" >nul 2>&1
        copy /Y "SKILL.md" "!OPENCLAW_SKILLS!\guardclaw\SKILL.md" >nul
        echo [OK] GuardClaw skill installed to OpenClaw.
        echo      Your agent will now use GuardClaw before executing tools.
    )
) else (
    echo [INFO] OpenClaw not detected. Skipping skill install.
    echo        To integrate: copy SKILL.md to %%USERPROFILE%%\.openclaw\workspace\skills\guardclaw\
)

:: ── Done ─────────────────────────────────────────────────────────
echo.
echo  ========================================================
echo   GuardClaw installed successfully!
echo.
echo   Launch GUI:  !PYTHON! guardclaw.py
echo   CLI scan:    !PYTHON! guardclaw.py --scan script.py
echo   Library:     from guardclaw import Protector
echo  ========================================================
echo.
pause
