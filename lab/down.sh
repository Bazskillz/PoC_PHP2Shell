#!/bin/bash
# Stop and clean up the CVE-2026-109618 lab
set -e
cd "$(dirname "$0")"

echo "[*] Stopping lab..."
docker compose down -v --remove-orphans
echo "[+] Lab stopped and cleaned up."
