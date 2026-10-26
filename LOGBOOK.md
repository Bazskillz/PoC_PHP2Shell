# LOGBOOK — PHP2Shell (CVE-2026-109618 / CVE-2026-109619) Audit

## 2026-10-25 — Session Start

### Decision: Target Selection
- **Target:** CVE-2026-109618 (RCE via OOM corruption in PHP)
- **Companion:** CVE-2026-109619 (use-after-free / stale global state across requests)
- **Nickname:** PHP2Shell
- **Rationale:** Critical (CVSS v4.0 9.2), unauthenticated RCE, default config, server-side, 22.6M+ exposed instances per Unit42. Fixes released 2026-10-21 (4 days ago). High acceptance rate expected: server-side, default config, no auth required.

### CVE-2026-109618 Research Summary
- **Advisory:** GHSA-w8hw-w9fx-j79w
- **CWEs:** CWE-416 (Use After Free), CWE-755 (Improper Handling of Exceptional Conditions), CWE-824 (Access of Uninitialized Pointer), CWE-1325 (Improperly Controlled Sequential Memory Allocation), CWE-1419 (Incorrect Initialization of Resource)
- **Root Cause:** PHP uses `longjmp()` for OOM errors. When allocation fails during request initialization, counters in `zend_hash.c` (`_zend_hash_str_add_or_update_i()`) are incremented before key allocation. OOM aborts via longjmp, leaving half-initialized bucket. Request shutdown iterates all counted buckets, interpreting uninitialized memory as valid PHP values.
- **Key file:** `Zend/zend_hash.c` — `_zend_hash_str_add_or_update_i()` increments `ht->nNumUsed++` and `ht->nNumOfElements++` before `zend_string_init()` for the key.
- **Trigger:** Crafted multipart POST requests with nested array field names. Multipart can bypass `post_max_size` checks. Unlimited headers per part, empty file controls, nested field names all amplify memory usage.
- **SAPI:** mod_php confirmed (calls shutdown even when startup fails). PHP-FPM exits child on startup failure (blocks this path), but post-startup OOM may still reach it. FrankenPHP likely susceptible.
- **Exploit stages (Datadog):**
  1. Reach interrupted insertion via crafted field-name sizes
  2. Heap grooming to control leftover bytes (fake PHP value)
  3. Shutdown follows fake structure, calls destructor → `system()` with attacker command
- **ASLR bypass:** PHPSESSID-based memory disclosure (credited to Wiz)
- **Fix approach:** Removes `longjmp()` for OOM. Adds soft OOM (deferred to VM safe point) and hard OOM (`_exit(137)`). The `zend_hash.c` counter ordering is unchanged — fix is in error handling around it.
- **Fix commit (tested build):** `678778973bb4d4185c06ef1320de50f1a975d3c8` (PHP 8.5.11, pre-fix)
- **Fix commit (patch):** `31c0ea7d7ff1d1fccb6492e52dab544011628065`
- **Fixed versions:** 8.2.35, 8.3.36, 8.4.27, 8.5.12

### CVE-2026-109619 Research Summary
- **Advisory:** GHSA-6wmf-4rv5-p3rp
- **Root Cause:** Worker-wide fields point to per-request memory. Fatal errors interrupt state cleanup, leaving stale pointers. Later request dereferences freed memory.
- **Confirmed paths:**
  - Fatal-error backtraces (PHP 8.5 only, `fatal_error_backtraces` enabled by default)
  - Session upload progress (enabled by default, runs before `session_start()`, affects mod_php AND PHP-FPM)
- **FPM attack:** Request 1 leaves state → fatal error → Request 2 on same worker consumes stale state via upload progress

### Sources Consulted
- Rapid7 ETR blog post
- Datadog SecurityLabs technical analysis
- Sansec research page
- GitHub Advisory GHSA-w8hw-w9fx-j79w
- Unit42 (Palo Alto Networks) threat brief
- Huntress rapid response
- watchTowr FAQ

### Decision: Focus on CVE-2026-109618 first
- More concrete code-level details available (zend_hash.c)
- mod_php path is clearest (shutdown runs even on startup failure)
- OOM trigger is well-understood (multipart + nested arrays)
- Memory disclosure via PHPSESSID provides ASLR bypass path

### Source Audit Findings (2026-10-25)

#### Vulnerable Code: `Zend/zend_hash.c:962-965` (8.4.26)
```c
add_to_hash:
    idx = ht->nNumUsed++;      // line 962 — counter incremented
    ht->nNumOfElements++;       // line 963 — counter incremented  
    p = ht->arData + idx;       // line 964 — bucket pointer set
    p->key = key = zend_string_init(str, len, ...); // line 965 — ALLOCATION CAN OOM HERE
```
If `zend_string_init()` triggers OOM → `longjmp()` via `zend_bailout()`. Bucket at `idx` is counted but uninitialized (no key, no value).

#### mod_php Request Lifecycle: `sapi/apache2handler/sapi_apache2.c:664-730`
```
zend_first_try {
    if (php_apache_request_ctor(r, ctx) != SUCCESS) {
        zend_bailout();  // line 672 — jumps to zend_end_try
    }
    ...
    php_execute_script(&zfd);  // line 717
} zend_end_try();              // line 727

// ALWAYS runs, even after bailout from failed startup:
php_apache_request_dtor(r);    // line 730 → php_request_shutdown(NULL)
```
**Key insight:** `php_request_shutdown()` walks `$_POST` hash table, visits every counted bucket (including the uninitialized one), interprets garbage memory as PHP values, and calls destructors on them.

#### Session Upload Progress: `ext/session/session.c:3221-3316`
- `php_session_rfc1867_callback()` runs during multipart parsing (BEFORE application code)
- Enabled by default (`session.upload_progress.enabled=1`)
- Triggered by `PHP_SESSION_UPLOAD_PROGRESS` field name in POST
- Starts session, decodes/encodes session data — can access stale state from prior requests

#### Fix Pattern (8.4.27)
1. **Allocator:** `longjmp()` removed. New `zend_mm_delayed_error()` queues OOM, sets `vm_interrupt`, checked at next safe point.
2. **Hard limit:** New `memory_hard_limit_percent` — exceeding it calls `_exit(137)`, no cleanup at all.
3. **Fallible allocations:** New `femalloc()`, `fpemalloc()` return NULL instead of longjmp. Hash table operations propagate `HASH_FALLIBLE` flag and return `HASH_NOMEM`.
4. **Session:** Added `in_rfc1867_update` flag, `php_session_unserialize_init()` restricts deserialization during upload progress to incomplete classes only.
5. **Note:** `zend_hash.c` counter ordering UNCHANGED in 8.4.27 — the fix is in the error path, not the data structure.

#### Diff Stats (Zend/ non-test files changed)
- `zend_alloc.c/h` — core OOM handling rewrite
- `zend_hash.c/h` — fallible allocation variants
- `zend.c/h` — delayed OOM state, vm_interrupt
- `zend_execute.c` — OOM interrupt check in VM
- `zend_globals.h` — new `delayed_oom` struct
- `main/main.c` — `memory_hard_limit_percent`, early rinit
- `ext/session/session.c` — `in_rfc1867_update` safety
- ~60+ new OOM test files

### Base PoC Results (2026-10-25)

**OOM Primitive: CONFIRMED**
- Method: 999 fields with ~135KB string keys under array syntax, chunked transfer encoding
- Target: PHP 8.4.26 + Apache mod_php, default config (memory_limit=128M, post_max_size=8M)
- Result: `Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 135168 bytes) in Unknown on line 0`
- "in Unknown on line 0" confirms OOM during request parsing, before application code
- Allocation size 135168 bytes matches key size — this is `zend_string_init()` in `_zend_hash_str_add_or_update_i()`
- Worker survived (non-crash path — crucial for multi-stage exploitation)
- Chunked encoding bypasses `post_max_size=8M` check (Content-Length is unknown)

**Docker Lab:**
- Server: `php:8.4.26-apache` with prefork MPM, default config
- Client: `python:3.12-slim` unprivileged container on same Docker network
- Scripts: up.sh, down.sh, shell.sh, client.sh
- One-command reproducible: `./lab/up.sh && ./lab/client.sh`

**Fix Verification (8.4.27):**
- Same payload against PHP 8.4.27 → 200 OK, no OOM
- Server log: "Actual POST length does not match Content-Length, and exceeds 8388608 bytes"
- Fix added actual-bytes check for chunked encoding, not just Content-Length
- Comprehensive fix confirmed: soft OOM + hard OOM + fallible allocs + post_size enforcement

**Discarded approaches:**
- Small fields with many parts: blocked by `max_multipart_body_parts` (1020) 
- Fields without array syntax: don't hit the vulnerable `_zend_hash_str_add_or_update_i()` string-key path
- Per-part header amplification: headers freed between parts (transient memory)
- Regular Content-Length: rejected by `post_max_size=8M` check

### Deep Fix Analysis (2026-10-25)

The fix at `zend_alloc.c:533-567` (`zend_mm_check_limit()`) is more nuanced than initially understood:

**Soft limit exceeded (memory_limit):**
- Queues delayed OOM via `zend_mm_delayed_error()` → sets `vm_interrupt`
- Returns `SUCCESS` — the allocation PROCEEDS past the limit
- The hash bucket IS fully initialized (key + value)
- Delayed OOM fires at next VM interrupt check (safe point)
- Result: no half-initialized state, counter ordering doesn't matter

**Hard limit exceeded (memory_hard_limit_percent):**
- Calls `_exit(137)` — process dies immediately
- No cleanup, no request shutdown, no hash iteration
- Result: no uninitialized access

**Fallible allocation path (HASH_FALLIBLE):**
- Returns `FAILURE` — caller returns `HASH_NOMEM`
- No counter increment, no allocation attempt
- Result: clean error propagation

**Key insight:** The counter ordering in `zend_hash.c` is intentionally unchanged because ALL allocation paths are now safe. The fix is in the error handling, not the data structure. This is a stronger fix than reordering counters would be.

**Residual `zend_bailout()` at line 3691-3692:**
- Only called from the DELAYED OOM handler (`zend_mm_handle_oom()`)
- Only when `!execute_data` (no PHP execution context)
- By this point, the allocation that triggered OOM has ALREADY completed
- The hash bucket is fully initialized before bailout fires
- So bailout at this point is safe — no half-initialized state

### CVE-2026-115560 (Related, published 2026-10-23)
- Mentioned by Rapid7 as published by PHP Foundation
- Reportedly has mitigation but no full patch
- Exploitation relies on non-standard configuration
- Limited public information available as of 2026-10-25
- Not included in our primary analysis scope (focuses on non-default config)

### Decision: No new 0-day in the fix itself
The fix design prevents half-initialized state by allowing allocations to succeed past the soft limit. The `longjmp()` in the delayed handler only fires after the critical section is complete. The counter ordering is not a vulnerability in the fixed version.

### Variant Hunt Results — Zend Engine (2026-10-25)

**Result: No actionable new variants found in 8.4.27**

The soft-OOM allocator fix broadly protects ALL mutation-before-allocation patterns:
- Allocations succeed past the soft limit (no half-initialized state)
- Hard limit causes `_exit(137)` (no cleanup, no access to invalid state)
- Fallible wrappers return FAILURE (clean error propagation)

Patterns examined:
1. `zend_hash.c:1122-1126` — original site, counter ordering unchanged but SAFE (allocs succeed)
2. `zend_alloc.c:3691-3692` — residual `zend_bailout()` during delayed OOM, SAFE (allocations already completed)
3. `zend_compile.c` — various counter+realloc patterns, SAFE (soft OOM protects)
4. `zend_API.c` — property count patterns, NOT reachable from network (module startup)
5. `zend_execute.c` — property info patterns, SAFE (soft OOM protects)

Residual risks noted:
- Older branches (7.4, 8.0, 8.1) may have incomplete backports
- Custom SAPI modules using old hash APIs not protected by fallible wrappers
- `mmap()` failures under `memory_limit=-1` can still trigger bailout (advisory acknowledges this)

### Variant Hunt Results — Extensions / SAPI / Main (2026-10-25)

**Result: No actionable new variants found in 8.4.27**

The fix patched ~100+ files across extensions, main, and Zend. All network-reachable input paths have OOM guards.

#### Files patched with OOM guards (key ones):
- `main/rfc1867.c` — 20+ `ZEND_HAS_OOM()` checks in multipart parser
- `main/php_variables.c` — OOM checks in POST variable registration and nested array loop
- `main/SAPI.c` — `zend_handle_delayed_oom()` called after POST handler returns
- `ext/filter/filter.c` — fallible allocation (`ZVAL_FSTRINGL`) + OOM checks
- `ext/json/json_parser.y` — failure checks on object/array create/append
- `ext/mbstring/mb_gpc.c` — `fecalloc()` (fallible) + `ZEND_HAS_OOM()` in GPC parsing
- `ext/soap/` — 6 OOM checks in encoding, HTTP, and SDL handling

#### Files NOT patched (potential defense-in-depth gaps):
1. **`sapi/apache2handler/sapi_apache2.c`** — Unconditional `php_apache_request_dtor()` (shutdown) after `zend_end_try()` is UNCHANGED. Fix relies entirely on allocator-level protection. Not a vulnerability in 8.4.27 (allocations succeed past soft limit), but the structural pattern remains.
2. **`sapi/fpm/fpm/fpm_main.c`** — No changes. FPM already exits child on startup failure, so less exposed.
3. **`ext/session/session.c`** — ZERO `ZEND_HAS_OOM()` checks in the entire extension. Session upload progress callback does `zend_hash_update()` + `php_session_flush()` without checking OOM state. In 8.4.27, allocations succeed (soft OOM deferred), so data is valid. Defense-in-depth gap, not exploitable.
4. **`ext/xmlreader/`, `ext/xmlwriter/`, `ext/tidy/`** — Zero OOM checks, but these require application code to invoke (not reachable during request startup).

#### Counter-before-allocation pattern analysis:
- `zend_hash.c` has 6 `nNumUsed++` locations
- Only `_zend_hash_str_add_or_update_i()` (line 1122 in 8.4.27) allocates AFTER the counter
- All other sites (`_zend_hash_add_or_update_i`, `_zend_hash_index_add_or_update_i`, `_zend_hash_append*`) take pre-allocated keys — no allocation after counter
- **The vulnerable pattern exists in exactly ONE location**

#### mmap failure analysis:
- `zend_mm_chunk_alloc` failure → `zend_out_of_memory()` → `exit(1)` — process dies, no cleanup, safe
- No `longjmp()` path for mmap failures in 8.4.27

#### Shutdown OOM state:
- `php_request_shutdown()` clears OOM state at line 1930 (`ZEND_OOM_STATE_NONE`)
- Allocations during shutdown can exceed limits again but OOM is never re-handled
- By design: shutdown needs to allocate for cleanup

### Decision: Variant hunt complete — no new 0-day
The fix comprehensively addresses the vulnerability class. The soft-OOM allocator change broadly protects all mutation-before-allocation patterns, not just the hash table one. Defense-in-depth gaps exist (session extension lacks OOM checks, mod_php SAPI unchanged) but these are not exploitable in 8.4.27 due to the allocator-level protection.

### Next Steps
1. Write FINDINGS.md
2. Wrap up (outcomes.md, move to finished_audits)
