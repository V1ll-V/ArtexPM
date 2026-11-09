#!/usr/bin/env python3
"""
CTF Remote Target Probe Tool (ctf_probe_target / ctf-probe)
Probes remote CTF target network connectivity, protocol, banner, TLS, HTTP,
Proof-of-Work (PoW) challenges, and interactive menus.
"""

import sys
import os
import re
import socket
import ssl
import time
import json
import urllib.parse

def parse_target(raw_target):
    raw = raw_target.strip()
    
    # Check if format is "nc <host> <port>"
    nc_match = re.match(r'^(?:nc|ncat|netcat)\s+(?:-v\s+)?([a-zA-Z0-9.\-_]+)\s+(\d+)$', raw)
    if nc_match:
        return nc_match.group(1), int(nc_match.group(2)), "tcp"
        
    # Check if format is URL: http:// or https://
    if raw.startswith("http://") or raw.startswith("https://"):
        u = urllib.parse.urlsplit(raw)
        scheme = u.scheme.lower()
        host = u.hostname
        port = u.port
        if not port:
            port = 443 if scheme == "https" else 80
        return host, port, scheme
        
    # Check if format is host:port
    if ":" in raw and not raw.startswith("["):
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0].strip(), int(parts[1]), "tcp"
            
    # Check if format is "host port"
    parts = raw.split()
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1]), "tcp"
        
    # Default single host/domain
    return raw, 80, "tcp"

def detect_pow(text):
    """
    Detects Proof-of-Work challenge patterns commonly used in CTFs.
    """
    if not text:
        return False, None
        
    patterns = [
        # sha256(xxxx + ??) == yyyy or sha256(???? + xxxx) == yyyy
        (r'(sha256\s*\(\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*\+\s*([?xX]+|\w+)\s*\)\s*==\s*([0-9a-fA-F]{4,64}))', "sha256"),
        (r'(sha256\s*\(\s*([?xX]+|\w+)\s*\+\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*\)\s*==\s*([0-9a-fA-F]{4,64}))', "sha256"),
        # md5(...)
        (r'(md5\s*\(\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*\+\s*([?xX]+|\w+)\s*\)\s*==\s*([0-9a-fA-F]{4,32}))', "md5"),
        # hashcash
        (r'(hashcash\s+-[a-zA-Z0-9\s\-]+)', "hashcash"),
        # generic CTF pow prompt
        (r'((?:please\s+)?(?:solve|give|provide)\s+(?:the\s+)?proof[- ]of[- ]work[^\n\r]*)', "proof_of_work"),
        (r'((?:pow|proof[- ]of[- ]work)\s*challenge[^\n\r]*)', "proof_of_work"),
        (r'(python3?\s+pow\.py\s+[^\n\r]*)', "pow_script"),
    ]
    
    for pat, pow_type in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return True, {
                "type": pow_type,
                "matched_text": m.group(1).strip()
            }
            
    return False, None

def detect_interactive_menu(text):
    """
    Detects interactive game/service menus.
    """
    if not text:
        return False, None
        
    # Check for numbered options: 1. ... 2. ...
    menu_matches = re.findall(r'^\s*([0-9]+)\s*[\.\)\]]\s*([^\r\n]+)', text, re.MULTILINE)
    if len(menu_matches) >= 2:
        return True, [f"{num}. {label.strip()}" for num, label in menu_matches[:10]]
        
    # Check for prompts
    prompt_match = re.search(r'([Cc]hoice|[Oo]ption|[Aa]ction|[Cc]ommand|[Pp]assword|[Uu]sername|[Kk]ey|[Tt]oken|[Nn]ame)\s*[:\?>]\s*$', text)
    if prompt_match:
        return True, [f"Prompt detected: {prompt_match.group(0).strip()}"]
        
    return False, None

def probe_target(target_str, timeout=10.0):
    host, port, hint_scheme = parse_target(target_str)
    res = {
        "target": target_str,
        "host": host,
        "port": port,
        "resolved_ip": None,
        "dns_time_ms": None,
        "tcp_connected": False,
        "rtt_ms": None,
        "protocol": hint_scheme,
        "tls_supported": False,
        "banner": None,
        "pow_detected": False,
        "pow_info": None,
        "interactive_menu": False,
        "menu_items": None,
        "http_info": None,
        "suggested_command": None,
        "error": None
    }
    
    # 1. DNS Resolution
    t0 = time.time()
    try:
        ip = socket.gethostbyname(host)
        res["resolved_ip"] = ip
        res["dns_time_ms"] = round((time.time() - t0) * 1000, 2)
    except Exception as e:
        res["error"] = f"DNS resolution failed: {e}"
        return res
        
    # 2. TCP Handshake
    t1 = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        res["tcp_connected"] = True
        res["rtt_ms"] = round((time.time() - t1) * 1000, 2)
    except Exception as e:
        res["error"] = f"TCP connection failed to {host}:{port} ({ip}): {e}"
        try:
            sock.close()
        except Exception:
            pass
        return res
        
    # 3. Banner grab (check if server speaks first)
    banner_bytes = b""
    sock.settimeout(min(2.5, timeout))
    try:
        banner_bytes = sock.recv(8192)
    except socket.timeout:
        pass
    except Exception:
        pass
        
    if banner_bytes:
        res["banner"] = banner_bytes.decode('utf-8', errors='replace')
        # Check if banner is HTTP response
        if banner_bytes.startswith(b"HTTP/1."):
            res["protocol"] = "http"
        else:
            res["protocol"] = "tcp_raw"
    else:
        # Server didn't speak first. Let's probe HTTP or check TLS.
        if hint_scheme in ("http", "https") or port in (80, 8080, 8000, 8888, 5000):
            try:
                http_req = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: ARTEX-CTF-Probe/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                sock.sendall(http_req.encode())
                sock.settimeout(3.0)
                resp = sock.recv(16384)
                if resp.startswith(b"HTTP/"):
                    res["protocol"] = "http"
                    res["banner"] = resp.decode('utf-8', errors='replace')
            except Exception:
                pass
                
    sock.close()
    
    # 4. If still no protocol confirmed, or if port 443/hint_scheme is https, test TLS
    if hint_scheme == "https" or port in (443, 8443) or (res["banner"] and b"\x15\x03" in banner_bytes):
        tls_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tls_sock.settimeout(timeout)
        try:
            tls_sock.connect((ip, port))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssock = ctx.wrap_socket(tls_sock, server_hostname=host)
            res["tls_supported"] = True
            if res["protocol"] == "http" or hint_scheme == "https":
                res["protocol"] = "https"
            else:
                res["protocol"] = "tls_raw"
            ssock.close()
        except Exception:
            pass
        finally:
            try:
                tls_sock.close()
            except Exception:
                pass

    # 5. Analyze banner / HTTP response
    full_text = res["banner"] or ""
    
    # HTTP Details
    if res["protocol"] in ("http", "https") and full_text.startswith("HTTP/"):
        parts = full_text.split("\r\n\r\n", 1)
        headers = parts[0].split("\r\n")
        status_line = headers[0] if headers else ""
        server_hdr = ""
        for h in headers[1:]:
            if h.lower().startswith("server:"):
                server_hdr = h.split(":", 1)[1].strip()
                break
        title = ""
        if len(parts) > 1:
            title_m = re.search(r'<title>(.*?)</title>', parts[1], re.IGNORECASE | re.DOTALL)
            if title_m:
                title = title_m.group(1).strip()
        res["http_info"] = {
            "status_line": status_line,
            "server": server_hdr,
            "title": title
        }
        
    # Proof of work detection
    is_pow, pow_info = detect_pow(full_text)
    if is_pow:
        res["pow_detected"] = True
        res["pow_info"] = pow_info
        
    # Interactive menu detection
    is_menu, menu_items = detect_interactive_menu(full_text)
    if is_menu:
        res["interactive_menu"] = True
        res["menu_items"] = menu_items

    # 6. Generate Suggested Connection Command
    if res["protocol"] == "https":
        res["suggested_command"] = f"curl -k -v https://{host}:{port}/"
    elif res["protocol"] == "http":
        res["suggested_command"] = f"curl -v http://{host}:{port}/"
    elif res["protocol"] == "tls_raw":
        res["suggested_command"] = f"openssl s_client -connect {host}:{port} -quiet"
    else:
        res["suggested_command"] = f"nc {host} {port}"
        
    return res

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: probe_target.py <target> [--json] [--timeout=N]")
        print("Examples:")
        print("  probe_target.py 10.10.10.10:9999")
        print("  probe_target.py 'nc 10.10.10.10 9999'")
        print("  probe_target.py http://10.10.10.10:8080/")
        sys.exit(1)
        
    target = sys.argv[1]
    is_json = "--json" in sys.argv
    timeout = 10.0
    for a in sys.argv[2:]:
        if a.startswith("--timeout="):
            try:
                timeout = float(a.split("=", 1)[1])
            except ValueError:
                pass
                
    result = probe_target(target, timeout=timeout)
    
    if is_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
        
    # Human-readable summary
    print("=" * 60)
    print(f" CTF Remote Target Probe: {target}")
    print("=" * 60)
    if result["error"]:
        print(f"[!] Error: {result['error']}")
        return
        
    print(f"[+] Target Host    : {result['host']} ({result['resolved_ip']})")
    print(f"[+] Port / Protocol: {result['port']} / {result['protocol'].upper()}")
    print(f"[+] RTT (Ping)     : {result['rtt_ms']} ms (DNS: {result['dns_time_ms']} ms)")
    if result['tls_supported']:
        print(f"[+] TLS / SSL      : Supported")
    if result.get("http_info"):
        hi = result["http_info"]
        print(f"[+] HTTP Status    : {hi['status_line']}")
        if hi['server']:
            print(f"[+] Server Header  : {hi['server']}")
        if hi['title']:
            print(f"[+] Page Title     : {hi['title']}")
    if result["pow_detected"]:
        print(f"[!] Proof-of-Work  : DETECTED! Type: {result['pow_info']['type']}")
        print(f"    Match          : {result['pow_info']['matched_text']}")
    if result["interactive_menu"]:
        print(f"[+] Interactive Menu: DETECTED ({len(result.get('menu_items', []))} options)")
        for item in result.get('menu_items', []):
            print(f"    * {item}")
    if result.get("banner"):
        print("-" * 60)
        print("Banner / Initial Output:")
        b_lines = result["banner"].splitlines()
        for l in b_lines[:15]:
            print("  " + l)
        if len(b_lines) > 15:
            print(f"  ... ({len(b_lines) - 15} more lines)")
    print("-" * 60)
    print(f"Suggested Command  : {result['suggested_command']}")
    print(f"pwntools snippet   : remote('{result['host']}', {result['port']}{', ssl=True' if result['protocol'] == 'tls_raw' or result['tls_supported'] else ''})")
    print("=" * 60)

if __name__ == "__main__":
    main()
