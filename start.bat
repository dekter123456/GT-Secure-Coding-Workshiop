@echo off
REM เริ่มเซิร์ฟเวอร์สำหรับ Secure Coding Workshop บน Windows
cd /d "%~dp0"
if "%PORT%"=="" set PORT=8000

where node >nul 2>nul
if %errorlevel%==0 (
  echo เริ่มด้วย Node...
  node server.js
  goto :eof
)

where python >nul 2>nul
if %errorlevel%==0 (
  echo ไม่พบ Node, เริ่มด้วย Python ที่ http://localhost:%PORT%
  python -m http.server %PORT%
  goto :eof
)

echo ไม่พบทั้ง Node และ Python — กรุณาติดตั้งอย่างใดอย่างหนึ่ง
