# Outcomes — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

## Upstream Response

| Item | Status | Date |
|------|--------|------|
| CVE-2026-109618 reported (by lcfr-hax) | Reported | 2026-08-11 |
| CVE reported (by Wiz, sagitzadik-wiz) | Reported | 2026-08-24 |
| Details leaked | Leaked | 2026-10-20 |
| PHP releases 8.2.35, 8.3.36, 8.4.27, 8.5.12 | Fixed | 2026-10-21 |
| GHSA-w8hw-w9fx-j79w published | Published | 2026-10-21 |
| Source backports for 7.4, 8.0, 8.1 | Published | 2026-10-21 |
| CVE-2026-115560 (related, reported by PHP Foundation) | Published | 2026-10-23 |

## Our Analysis

| Item | Status | Date |
|------|--------|------|
| Initial research complete | Done | 2026-10-25 |
| Source audit complete | Done | 2026-10-25 |
| Docker lab built and tested | Done | 2026-10-25 |
| Base PoC (OOM trigger) confirmed | Done | 2026-10-25 |
| Fix verified (8.4.27 handles payload safely) | Done | 2026-10-25 |
| Variant hunting (Zend engine) | Done — no new variants | 2026-10-25 |
| Variant hunting (extensions/SAPI) | Done — no new variants | 2026-10-25 |
| FINDINGS.md complete | Done | 2026-10-25 |
| Audit complete | Done | 2026-10-25 |

## Key Findings

1. **OOM primitive confirmed:** 999 array fields with ~135KB keys via chunked POST exhausts 128MB memory_limit before any PHP code runs
2. **Fix verified:** PHP 8.4.27 handles the same payload safely (rejects early, no OOM)
3. **No new 0-day found:** The soft-OOM allocator fix comprehensively protects all mutation-before-allocation patterns
4. **Vulnerable pattern is unique:** Only ONE location in the codebase (`_zend_hash_str_add_or_update_i()`) has the counter-before-allocation pattern
5. **Defense-in-depth gaps noted:** Session extension has zero `ZEND_HAS_OOM()` checks; mod_php SAPI unconditional shutdown unchanged. Neither is exploitable in 8.4.27.

## Notes

- This is a KNOWN, PATCHED vulnerability (CVE assigned 2026-10-21)
- Our analysis is for defensive purposes: understanding the attack surface, building detection capabilities, and verifying patch effectiveness
- No new 0-day discovered — the fix in 8.4.27 is comprehensive
- The fix addresses multiple vectors: soft OOM (delayed), hard OOM (`_exit`), fallible allocations, chunked encoding size check, session deserialization restrictions
