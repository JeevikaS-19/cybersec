@echo off
rem Lint + tests. Run by the Stop hook. Skips steps whose tools or files are missing.
setlocal
cd /d "%~dp0.."
set FAILED=0

python -m ruff --version >nul 2>&1
if errorlevel 1 (
  echo verify: ruff not installed, lint skipped 1>&2
) else (
  python -m ruff check . 1>&2 || set FAILED=1
)

if not exist tests\ (
  echo verify: no tests\ folder, tests skipped 1>&2
  goto done
)
python -m pytest --version >nul 2>&1
if errorlevel 1 (
  echo verify: pytest not installed, tests skipped 1>&2
  goto done
)
python -m pytest -q -m "not slow and not docker" 1>&2 || set FAILED=1

:done
rem Exit 1 = non-blocking: failures are shown to you, Claude is not forced to fix them.
if "%FAILED%"=="1" exit /b 1
exit /b 0
