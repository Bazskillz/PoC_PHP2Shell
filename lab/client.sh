#!/bin/bash
# Run the PoC from the unprivileged attacker container
# Proves no host access is required
docker exec cve2026109618-attacker python3 /poc/base_poc.py \
    --host php-vulnerable \
    --port 80 \
    --path /index.php \
    "$@"
