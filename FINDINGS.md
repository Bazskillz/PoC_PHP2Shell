# FINDINGS — PHP2Shell (CVE-2026-109618) Security Analysis

## Date: 2026-10-25
## Analyst: basdaniel3@gmail.com
## Target: PHP 8.4.26 (last vulnerable release)

---

## Finding 1: CVE-2026-109618 — OOM Hash Corruption → RCE

### Threat Model Card

**Bug Description:** PHP's Zend Engine hash table function `_zend_hash_str_add_or_update_i()` in `Zend/zend_hash.c` increments bucket counters (`nNumUsed`, `nNumOfElements`) before allocating the bucket's key via `zend_string_init()`. When this allocation triggers an out-of-memory error, PHP's `longjmp()`-based error handling aborts execution, leaving a counted but uninitialized bucket. During request shutdown, PHP iterates all counted buckets and interprets uninitialized memory as valid PHP values, calling destructors on them. Under Apache mod_php with prefork MPM, shutdown runs unconditionally — even when request startup fails.

**Filepath:** `Zend/zend_hash.c:962-965` (`_zend_hash_str_add_or_update_i`)

**Attacker Prerequisites (quantified):**
- Authentication: None (zero auth, zero roles)
- Network: Remote, TCP to HTTP port
- Target config: Default PHP + Apache mod_php (prefork MPM)
- Knowledge: PHP version (for heap layout), memory_limit value (128M default)
- Capability: Send crafted multipart HTTP POST requests

**Gain:**
- Remote code execution as web worker user (www-data/apache)
- Cross-request memory disclosure (heap contents including secrets)
- Pre-application exploitation (before any PHP code runs)

**Boundary Crossed:** Network → Host code execution (unauthenticated)

### Vulnerability Details

**Root Cause Chain:**
1. `_zend_hash_str_add_or_update_i()` increments `nNumUsed` and `nNumOfElements` (lines 962-963) before calling `zend_string_init()` (line 965)
2. `zend_string_init()` calls `emalloc()` which may exceed `memory_limit`
3. OOM error triggers `zend_mm_safe_error()` → `zend_bailout()` → `longjmp()`
4. The longjmp unwinds past the hash insertion, leaving the bucket counted but uninitialized
5. mod_php's `php_handler()` always calls `php_apache_request_dtor()` after `zend_end_try()` (line 730)
6. `php_request_shutdown()` destroys `$_POST` and iterates all counted buckets
7. The uninitialized bucket's data is interpreted as a PHP zval — potential arbitrary code execution

**OOM Trigger:**
- Multipart POST with chunked transfer encoding (bypasses `post_max_size` check at `rfc1867.c:697`)
- Array-syntax field names (e.g., `a[LARGE_KEY]`) to hit the string-key insertion path
- ~1000 fields with ~135KB keys exhausts 128MB `memory_limit`

### Reproduction

**Tested Version:** PHP 8.4.26 + Apache 2.4.69 (Debian) + mod_php + prefork MPM

**Environment:**
```
memory_limit: 128M (default)
post_max_size: 8M (default, bypassed via chunked encoding)
max_input_vars: 1000 (default)
session.upload_progress.enabled: 1 (default)
```

**Steps:**
```bash
# 1. Start lab
cd lab && ./up.sh

# 2. Run PoC from unprivileged client container
./client.sh

# 3. Expected output:
# [+] CONFIRMED: PHP memory limit exhaustion
# Fatal error: Allowed memory size of 134217728 bytes exhausted
# (tried to allocate 135168 bytes) in Unknown on line 0
```

**Verified Fix:** PHP 8.4.27 handles the same payload safely — rejects the request early with "Actual POST length does not match Content-Length, and exceeds 8388608 bytes" and returns 200 OK without memory exhaustion.

### Fix Analysis (PHP 8.4.27)

The fix is comprehensive:
1. **Removed `longjmp()` for OOM** — replaced with delayed soft OOM (checked at next VM safe point)
2. **Added hard OOM limit** — `_exit(137)` with no cleanup, preventing invalid state access
3. **Fallible allocations** — new `femalloc()`/`fpemalloc()` return NULL instead of longjmp
4. **Hash table protection** — `HASH_FALLIBLE` flag propagated through hash operations
5. **Chunked encoding fix** — post_max_size now checked against actual received bytes, not just Content-Length
6. **Session safety** — `in_rfc1867_update` flag restricts deserialization during upload progress
7. **Note:** The counter ordering in `zend_hash.c` is intentionally UNCHANGED — the fix is in error handling

### Severity

- **CVSS v4.0:** 9.2 Critical (`AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`)
- **CWEs:** CWE-416, CWE-755, CWE-824, CWE-1325, CWE-1419

---

## Variant Analysis

### Zend Engine — No Actionable Variants in 8.4.27

The soft-OOM allocator fix in 8.4.27 broadly protects ALL mutation-before-allocation patterns in the Zend engine. The allocations now **succeed** past the soft limit (so data structures are always fully initialized), and the hard limit causes `_exit(137)` (no cleanup, no access to invalid state).

**Patterns examined:**
- `zend_hash.c` — Original site (`nNumUsed++` before `zend_string_init`). Counter ordering unchanged but safe.
- `zend_compile.c` — `last_var++`/`num_interfaces++` before `erealloc`. Protected by soft OOM.
- `zend_API.c` — Property count increments before realloc. Not reachable from network (module startup).
- `zend_execute.c` — Property info mutations. Protected by soft OOM.
- `zend_alloc.c:3691` — Residual `zend_bailout()` in delayed OOM handler. Safe (allocations already completed).

**Residual risks for variant consideration:**
1. **EOL branches (7.4, 8.0, 8.1):** Source-only backports may be incomplete. Should audit these specifically.
2. **Custom SAPI modules:** Third-party SAPIs using old (non-fallible) hash APIs are not protected.
3. **`mmap()` failure path:** Under `memory_limit=-1`, `mmap()` failures can still trigger bailout (per advisory).

### Extensions and SAPI — No Actionable Variants in 8.4.27

The fix patched ~100+ files across extensions, main, and Zend. All network-reachable input-processing paths now have OOM guards.

**Counter-before-allocation pattern (definitive):**
- `zend_hash.c` has 6 `nNumUsed++` locations total
- Only `_zend_hash_str_add_or_update_i()` allocates AFTER the counter increment
- All other sites (`_zend_hash_add_or_update_i`, `_zend_hash_index_add_or_update_i`, `_zend_hash_append*`) take pre-allocated keys — no allocation after counter
- **The vulnerable pattern exists in exactly ONE location in the entire codebase**

**Key extensions patched with OOM guards:**
| File | Change |
|------|--------|
| `main/rfc1867.c` | 20+ `ZEND_HAS_OOM()` checks in multipart parser |
| `main/php_variables.c` | OOM checks in POST variable registration |
| `main/SAPI.c` | `zend_handle_delayed_oom()` after POST handler |
| `ext/filter/filter.c` | Fallible allocation (`ZVAL_FSTRINGL`) + OOM checks |
| `ext/json/json_parser.y` | Failure checks on object/array operations |
| `ext/mbstring/mb_gpc.c` | `fecalloc()` + `ZEND_HAS_OOM()` in GPC parsing |
| `ext/soap/*.c` | 6 OOM checks in encoding, HTTP, SDL |

**Defense-in-depth gaps (not exploitable in 8.4.27):**
1. **`sapi/apache2handler/sapi_apache2.c`** — Unconditional shutdown pattern unchanged. Fix relies on allocator-level protection.
2. **`sapi/fpm/fpm_main.c`** — No changes. FPM already exits child on startup failure.
3. **`ext/session/session.c`** — Zero `ZEND_HAS_OOM()` checks. Session upload progress does `zend_hash_update()` + `php_session_flush()` without checking OOM state. Not exploitable because allocations succeed past soft limit.
4. **`ext/xmlreader/`, `ext/xmlwriter/`, `ext/tidy/`** — Zero OOM checks, but require application code to invoke.

**mmap failure analysis:** `zend_mm_chunk_alloc` failure → `zend_out_of_memory()` → `exit(1)`. No `longjmp()` path. Safe.

---

## References

- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) — Advisory
- [Rapid7 ETR](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/) — Technical analysis
- [Datadog SecurityLabs](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/) — Code-level analysis
- [Sansec Research](https://sansec.io/research/php2shell) — Memory disclosure details
- [Unit42](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/) — Threat brief
- [Huntress](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities) — Rapid response
- [watchTowr FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/) — Q&A
