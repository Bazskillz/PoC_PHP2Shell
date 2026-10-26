# Security Analysis Report: CVE-2026-109618 (PHP2Shell)

## Threat Model Card

**Bug:** OOM-triggered hash table corruption in PHP's Zend Engine allows unauthenticated remote code execution. The function `_zend_hash_str_add_or_update_i()` in `Zend/zend_hash.c` increments bucket counters before key allocation. When the allocation fails due to memory exhaustion, `longjmp()` leaves a counted but uninitialized bucket. Apache mod_php's unconditional shutdown walks the corrupted hash table, interpreting attacker-controlled heap bytes as PHP values and calling destructors — redirectable to `system()`. Exploitation requires only crafted HTTP multipart POST requests with chunked transfer encoding; no authentication, no special configuration, no application-level vulnerability needed.

**Prerequisites:** Unauthenticated remote attacker, HTTP access, default PHP+Apache config  
**Gain:** RCE as web worker, cross-request memory disclosure  
**Boundary:** Network → host code execution  
**CVSS v4.0:** 9.2 Critical  

---

## 1. Executive Summary

CVE-2026-109618 is a critical unauthenticated remote code execution vulnerability in PHP's Zend Engine hash table implementation, affecting all PHP versions from 5.4.0 through 8.4.26 (and up to 8.5.11). The vulnerability was patched on 2026-10-21 in PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12.

The root cause is a state mutation (counter increment) before a potentially-failing memory allocation in `_zend_hash_str_add_or_update_i()`. PHP's `longjmp()`-based OOM error handling aborts the operation mid-flight, leaving inconsistent state that is later consumed during request shutdown.

## 2. Technical Analysis

### 2.1 Vulnerable Code Path

**File:** `Zend/zend_hash.c` (PHP 8.4.26)  
**Function:** `_zend_hash_str_add_or_update_i()`, lines 962-965

```c
add_to_hash:
    idx = ht->nNumUsed++;                    // STATE MUTATION: counter incremented
    ht->nNumOfElements++;                     // STATE MUTATION: counter incremented
    p = ht->arData + idx;                     // Pointer to uninitialized bucket
    p->key = key = zend_string_init(str, len, // ALLOCATION: can trigger OOM
                     GC_FLAGS(ht) & IS_ARRAY_PERSISTENT);
```

### 2.2 OOM Error Handling (Pre-Fix)

**File:** `Zend/zend_alloc.c` (PHP 8.4.26)

When `emalloc()` exceeds `memory_limit`, it calls `zend_mm_safe_error()` which uses `longjmp()` via `zend_bailout()` to unwind the stack. This aborts the hash insertion after the counters were incremented but before the bucket was initialized.

### 2.3 mod_php Shutdown Path

**File:** `sapi/apache2handler/sapi_apache2.c`, lines 664-730

```c
zend_first_try {
    if (php_apache_request_ctor(r, ctx) != SUCCESS) {
        zend_bailout();    // OOM during startup jumps here
    }
    php_execute_script(&zfd);
} zend_end_try();

// ALWAYS executes — even after bailout:
php_apache_request_dtor(r);  // → php_request_shutdown() → destroys $_POST
```

### 2.4 OOM Trigger Mechanism

- **Chunked transfer encoding** bypasses `post_max_size` check (which only examines `Content-Length`)
- Array-syntax field names (`a[LARGE_KEY]`) force string-key hash insertion via `_zend_hash_str_add_or_update_i()`
- ~999 fields with ~135KB keys consume ~128MB, exhausting default `memory_limit`
- OOM occurs "in Unknown on line 0" — during request parsing, before application code

### 2.5 Exploitation Stages

Per published analyses (Datadog, Rapid7):
1. **Trigger OOM:** Crafted multipart POST exhausts memory during hash insertion
2. **Control uninitialized bytes:** Heap grooming places attacker data where the bucket will be
3. **Redirect execution:** Shutdown walks the fake bucket, follows the fake PHP value structure to a destructor callback, resolving to `system()` with attacker-supplied command
4. **ASLR bypass:** PHPSESSID-based memory disclosure leaks heap pointers (credited to Wiz)

## 3. Reproduction

### 3.1 Lab Setup (One Command)

```bash
cd lab && ./up.sh
```

Creates:
- `cve2026109618-php`: PHP 8.4.26 + Apache mod_php (prefork), default config
- `cve2026109618-attacker`: Python 3.12 unprivileged client on same network

### 3.2 PoC Execution

```bash
./lab/client.sh
```

**Expected output:**
```
[+] CONFIRMED: PHP memory limit exhaustion
    Fatal error: Allowed memory size of 134217728 bytes exhausted
    (tried to allocate 135168 bytes) in Unknown on line 0
[+] === BASE PRIMITIVE CONFIRMED ===
```

### 3.3 Fix Verification

Same payload against PHP 8.4.27:
```
[*] Status: HTTP/1.1 200 OK
[-] 200 OK — request parsed without OOM
```

The fix rejects the oversized chunked body early: "Actual POST length does not match Content-Length, and exceeds 8388608 bytes"

## 4. Tested Versions

| Version | SAPI | Result |
|---------|------|--------|
| PHP 8.4.26 | Apache mod_php (prefork) | **VULNERABLE** — OOM triggered, primitive confirmed |
| PHP 8.4.27 | Apache mod_php (prefork) | **FIXED** — payload rejected safely |

## 5. Fix Analysis

PHP 8.4.27 implements a comprehensive fix:

1. **Soft OOM:** Delayed error via `zend_mm_delayed_error()`, checked at VM safe point
2. **Hard OOM:** `_exit(137)` when memory hits hard limit — no cleanup, no invalid state access
3. **Fallible allocations:** `femalloc()`, `fpemalloc()` return NULL instead of longjmp
4. **Hash table fallible ops:** `HASH_FALLIBLE` flag, `HASH_NOMEM` return value
5. **Post size enforcement:** Actual received bytes checked, not just Content-Length
6. **Session safety:** `in_rfc1867_update` restricts deserialization scope
7. **Counter ordering unchanged:** The fix is in error handling, not data structure ordering

## 6. Recommendations

1. **Immediate:** Update to PHP 8.4.27+ (or 8.3.36+, 8.2.35+, 8.5.12+)
2. **Interim mitigation:** Set `memory_limit=-1` administratively, set `session.upload_progress.enabled=0`, limit request sizes at reverse proxy/WAF
3. **Detection:** Monitor for "Allowed memory size" errors on line 0, anomalous PHPSESSID cookie lengths, multipart requests with very large field names
4. **Do not rely on:** `RLIMIT_AS`/`RLIMIT_DATA` (triggers the vulnerable mmap failure path), `display_errors=Off` (hides but doesn't prevent the bug)

## 7. Variant Analysis

### 7.1 Zend Engine Variants — None Found

The soft-OOM allocator fix broadly protects all mutation-before-allocation patterns. Allocations succeed past the soft limit (data structures fully initialized), and the hard limit triggers `_exit(137)`. The counter ordering in `zend_hash.c` is unchanged but safe.

### 7.2 Extension and SAPI Variants — None Found

The fix patched ~100+ files. All network-reachable input-processing paths now have OOM guards. The vulnerable counter-before-allocation pattern exists in exactly ONE location (`_zend_hash_str_add_or_update_i()`).

**Defense-in-depth gaps (not exploitable in 8.4.27):**
- `ext/session/session.c` has zero `ZEND_HAS_OOM()` checks — session upload progress does hash updates + flush without checking OOM state. Not exploitable because allocations succeed past soft limit.
- `sapi/apache2handler/sapi_apache2.c` unconditional shutdown pattern unchanged — fix relies on allocator-level protection.
- `ext/xmlreader/`, `ext/xmlwriter/`, `ext/tidy/` have zero OOM checks — but require application code to invoke.

### 7.3 Residual Risk Areas

1. **EOL branches (7.4, 8.0, 8.1):** Source-only backports may miss allocator changes in less-tested code paths
2. **Custom SAPI modules:** Third-party SAPIs using non-fallible hash APIs are not automatically protected
3. **`mmap()` failures:** Under `memory_limit=-1`, system-level allocation failures can still trigger bailout (acknowledged by advisory)

## 8. Upstream Disclosure Policy

- **Report to:** https://github.com/php/php-src/security/advisories/new
- **Fallback:** security@php.net
- **Format:** Short report, brief reproducer, state each point once
- **Note:** CVE-2026-109618 is already patched and publicly disclosed. New variant findings (if any) should be reported as new advisories.
