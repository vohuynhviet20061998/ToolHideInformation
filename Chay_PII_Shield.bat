@echo off
chcp 65001 >nul
cd /d "%~dp0"
python -c "import lxml, pymupdf" 2>nul || (
  echo Dang cai thu vien lan dau...
  python -m pip install -r requirements.txt
)
python pii_shield.py
if errorlevel 1 pause
