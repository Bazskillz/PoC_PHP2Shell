# PoC_PHP2Shell

Security research and proof-of-concept for **CVE-2026-109618** — an unauthenticated
remote code execution bug in PHP's Zend Engine hash table handling.

## Summary

`_zend_hash_str_add_or_update_i()` in `Zend/zend_hash.c` increments bucket counters
before allocating the bucket key. When that allocation fails under memory exhaustion,
`longjmp()`-based error handling leaves a counted but uninitialized bucket. Under
Apache `mod_php` (prefork MPM), request shutdown unconditionally walks the corrupted
hash table and interprets attacker-controlled heap bytes as PHP values, calling
destructors on them — redirectable to code execution.

- **Impact:** RCE as the web worker + cross-request memory disclosure
- **Prerequisites:** unauthenticated remote attacker, default PHP + Apache config
- **Affected:** PHP 8.4.26 (last vulnerable release); fixed in 8.4.27
- **CVSS v4.0:** 9.2 (Critical)

## Layout

| Path | Contents |
|------|----------|
| `FINDINGS.md` | Full technical findings and threat model |
| `disclosure/REPORT.md` | Disclosure report |
| `finished_audits/` | Completed CVE-2026-109618 audit (findings, report, threat model card) |
| `poc/` | Proof-of-concept (`base_poc.py`) and threat model card |
| `lab/` | Dockerized vulnerable/fixed test environment |
| `LOGBOOK.md` | Research logbook |
| `outcomes.md` | Outcomes summary |

The PHP source trees (`php-src-8.4.26/`, `php-src-8.4.27/`) are gitignored.

## Lab

A self-contained Docker environment for reproduction lives in `lab/`:

```sh
cd lab
./up.sh      # build and start the vulnerable server
./client.sh  # run the PoC client against it
./down.sh    # tear down
```

## Disclaimer

For authorized security research and defensive testing only. Use against systems you
own or have explicit permission to test.
