@echo off
rem ============================================================================
rem  Capture Analyzer launcher
rem  - Double-click to open the GUI (then use "Open Capture...").
rem  - Or drag a .pcapng file onto this file's icon to open it pre-loaded.
rem  Uses pythonw (no console window); falls back to python if pythonw is absent.
rem ============================================================================
set "PYW=pythonw"
where pythonw >nul 2>&1 || set "PYW=python"
start "" %PYW% "%~dp0analyze_gui.py" "%~1"
