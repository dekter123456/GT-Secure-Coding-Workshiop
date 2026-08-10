#!/usr/bin/env bash
# เริ่มเซิร์ฟเวอร์สำหรับ Secure Coding Workshop
# พยายามใช้ Node ก่อน ถ้าไม่มีค่อย fallback ไปใช้ Python
set -e
cd "$(dirname "$0")"

PORT="${PORT:-8000}"

if command -v node >/dev/null 2>&1; then
  echo "เริ่มด้วย Node..."
  PORT="$PORT" node server.js
elif command -v python3 >/dev/null 2>&1; then
  echo "ไม่พบ Node, เริ่มด้วย Python3 ที่ http://localhost:$PORT"
  python3 -m http.server "$PORT"
else
  echo "ไม่พบทั้ง Node และ Python3 — กรุณาติดตั้งอย่างใดอย่างหนึ่ง แล้วลองใหม่"
  exit 1
fi
