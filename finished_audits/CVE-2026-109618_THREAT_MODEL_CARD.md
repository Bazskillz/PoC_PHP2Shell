# Threat Model Card — CVE-2026-109618

## Bug Description
PHP's Zend Engine hash table implementation (`_zend_hash_str_add_or_update_i()`) increments bucket counters (`nNumUsed`, `nNumOfElements`) **before** allocating the bucket's key via `zend_string_init()`. When this allocation triggers an out-of-memory (OOM) error, PHP's `longjmp()`-based error handling aborts the operation, leaving a counted but uninitialized bucket. During request shutdown, `php_request_shutdown()` iterates all counted buckets in `$_POST`, interpreting uninitialized memory as valid PHP values and calling destructors on them. Under Apache mod_php, shutdown runs even when request startup fails (the `zend_first_try`/`zend_end_try` pattern in `sapi_apache2.c` always calls `php_apache_request_dtor()`).

## File Path
- **Vulnerable function:** `Zend/zend_hash.c:962-965` — `_zend_hash_str_add_or_update_i()`
- **OOM handler:** `Zend/zend_alloc.c` — `zend_mm_safe_error()` uses `longjmp()`
- **Shutdown path:** `sapi/apache2handler/sapi_apache2.c:729-730` — unconditional `php_apache_request_dtor()`
- **Multipart parser:** `main/rfc1867.c` — parses POST fields with nested array syntax
- **Session handler:** `ext/session/session.c:3221+` — upload progress callback runs pre-RINIT

## Attacker Prerequisites (quantified)
- **Authentication:** None (zero auth, zero roles)
- **Network position:** Remote, network-reachable to the target HTTP port
- **Target config:** Default PHP + Apache mod_php (prefork MPM). No application-level changes needed.
- **Required capabilities:** Send crafted HTTP multipart POST requests
- **Target state:** At least one Apache worker accepting requests
- **Knowledge required:** PHP version (for heap layout), `memory_limit` value (default 128M)

## Quantified Gain
- **Memory disclosure:** Server-side heap contents leaked via `Set-Cookie: PHPSESSID=` (passwords, session tokens, API keys, TLS private keys from other requests' memory)
- **Remote code execution:** Attacker-controlled fake PHP value in uninitialized bucket → destructor callback redirected to `system()` with attacker-supplied command string
- **Privilege:** Execution as the web server worker user (typically `www-data` or `apache`)
- **Persistence:** Worker survives successful exploitation (no crash required)

## Boundary Crossed
- **Network → Host code execution:** Unauthenticated remote attacker gains arbitrary code execution on the server
- **Cross-request information disclosure:** Memory from other users' requests (including secrets) leaked to attacker
- **Pre-application:** Exploitation occurs during request parsing, before any application code runs — no WAF/framework-level defense applies

## CVSS v4.0
9.2 Critical — `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`

## Affected Versions
- PHP 8.4.0 through 8.4.26 (fixed in 8.4.27)
- PHP 8.3.0 through 8.3.35 (fixed in 8.3.36)
- PHP 8.2.0 through 8.2.34 (fixed in 8.2.35)
- PHP 8.5.0 through 8.5.11 (fixed in 8.5.12)
- PHP 5.4.0 through 8.1.x (EOL, source-only backports available)
