#!/bin/bash
# Start the CVE-2026-109618 lab environment
set -e
cd "$(dirname "$0")"

echo "[*] Building and starting CVE-2026-109618 lab..."
docker compose build --no-cache
docker compose up -d

echo "[*] Waiting for PHP server to be ready..."
for i in $(seq 1 30); do
    if curl -s http://localhost:8080/index.php | grep -q "PHP.*OK"; then
        echo "[+] Server is ready!"
        echo ""
        echo "    PHP server: http://localhost:8080/index.php"
        echo "    Attacker:   docker exec -it cve2026109618-attacker bash"
        echo ""
        echo "[*] PHP version and config:"
        docker exec cve2026109618-php php -r 'echo "  Version: " . phpversion() . "\n";'
        docker exec cve2026109618-php php -r 'echo "  memory_limit: " . ini_get("memory_limit") . "\n";'
        docker exec cve2026109618-php php -r 'echo "  upload_progress: " . ini_get("session.upload_progress.enabled") . "\n";'
        docker exec cve2026109618-php php -r 'echo "  post_max_size: " . ini_get("post_max_size") . "\n";'
        docker exec cve2026109618-php php -r 'echo "  SAPI: " . php_sapi_name() . "\n";'
        exit 0
    fi
    sleep 1
done

echo "[-] Server did not start in 30 seconds"
docker compose logs php-vulnerable
exit 1
