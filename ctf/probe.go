package ctf

const ProbeTargetScript = `import sys, os, re, socket, ssl, time, json, urllib.parse

def parse_target(raw_target):
    raw = raw_target.strip()
    nc_match = re.match(r'^(?:nc|ncat|netcat)\s+(?:-v\s+)?([a-zA-Z0-9.\-_]+)\s+(\d+)$', raw)
    if nc_match:
        return nc_match.group(1), int(nc_match.group(2)), "tcp"
    if raw.startswith("http://") or raw.startswith("https://"):
        u = urllib.parse.urlsplit(raw)
        scheme = u.scheme.lower()
        host = u.hostname
        port = u.port or (443 if scheme == "https" else 80)
        return host, port, scheme
    if ":" in raw and not raw.startswith("["):
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0].strip(), int(parts[1]), "tcp"
    parts = raw.split()
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1]), "tcp"
    return raw, 80, "tcp"

def detect_pow(text):
    if not text:
        return False, None
    patterns = [
        (r'(sha256\s*\(\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*\+\s*([?xX]+|\w+)\s*\)\s*==\s*([0-9a-fA-F]{4,64}))', "sha256"),
        (r'(sha256\s*\(\s*([?xX]+|\w+)\s*\+\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*\)\s*==\s*([0-9a-fA-F]{4,64}))', "sha256"),
        (r'(md5\s*\(\s*["\']?([a-zA-Z0-9_\-]+)["\']?\s*\+\s*([?xX]+|\w+)\s*\)\s*==\s*([0-9a-fA-F]{4,32}))', "md5"),
        (r'(hashcash\s+-[a-zA-Z0-9\s\-]+)', "hashcash"),
        (r'((?:please\s+)?(?:solve|give|provide)\s+(?:the\s+)?proof[- ]of[- ]work[^\n\r]*)', "proof_of_work"),
        (r'((?:pow|proof[- ]of[- ]work)\s*challenge[^\n\r]*)', "proof_of_work"),
        (r'(python3?\s+pow\.py\s+[^\n\r]*)', "pow_script"),
    ]
    for pat, pow_type in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return True, {"type": pow_type, "matched_text": m.group(1).strip()}
    return False, None

def detect_interactive_menu(text):
    if not text:
        return False, None
    menu_matches = re.findall(r'^\s*([0-9]+)\s*[\.\)\]]\s*([^\r\n]+)', text, re.MULTILINE)
    if len(menu_matches) >= 2:
        return True, [f"{num}. {label.strip()}" for num, label in menu_matches[:10]]
    prompt_match = re.search(r'([Cc]hoice|[Oo]ption|[Aa]ction|[Cc]ommand|[Pp]assword|[Uu]sername|[Kk]ey|[Tt]oken|[Nn]ame)\s*[:\?>]\s*$', text)
    if prompt_match:
        return True, [f"Prompt detected: {prompt_match.group(0).strip()}"]
    return False, None

def probe_target(target_str, timeout=10.0):
    host, port, hint_scheme = parse_target(target_str)
    res = {
        "target": target_str, "host": host, "port": port,
        "resolved_ip": None, "dns_time_ms": None, "tcp_connected": False,
        "rtt_ms": None, "protocol": hint_scheme, "tls_supported": False,
        "banner": None, "pow_detected": False, "pow_info": None,
        "interactive_menu": False, "menu_items": None, "http_info": None,
        "suggested_command": None, "error": None
    }
    t0 = time.time()
    ip = None
    dns_err = None
    attempts = 0
    for attempt in range(3):
        attempts = attempt + 1
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            if infos:
                ip = infos[0][4][0]
                break
        except Exception as e:
            dns_err = e
            if attempt < 2:
                time.sleep(0.3 * (attempt + 1))
    if not ip:
        try:
            import subprocess
            p = subprocess.run(["getent", "ahostsv4", host], capture_output=True, text=True, timeout=3)
            if p.returncode == 0 and p.stdout.strip():
                ip = p.stdout.strip().splitlines()[0].split()[0]
        except Exception:
            pass
    res["dns_attempts"] = attempts
    if not ip:
        res["error"] = f"DNS resolution failed: {dns_err}"
        return res
    res["resolved_ip"] = ip
    res["dns_time_ms"] = round((time.time() - t0) * 1000, 2)

    t1 = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        res["tcp_connected"] = True
        res["rtt_ms"] = round((time.time() - t1) * 1000, 2)
    except Exception as e:
        res["error"] = f"TCP connection failed to {host}:{port} ({ip}): {e}"
        try: sock.close()
        except Exception: pass
        return res

    banner_bytes = b""
    sock.settimeout(min(2.5, timeout))
    try: banner_bytes = sock.recv(8192)
    except Exception: pass

    if banner_bytes:
        res["banner"] = banner_bytes.decode('utf-8', errors='replace')
        res["protocol"] = "http" if banner_bytes.startswith(b"HTTP/1.") else "tcp_raw"
    else:
        if hint_scheme in ("http", "https") or port in (80, 8080, 8000, 8888, 5000):
            try:
                http_req = f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUser-Agent: ARTEX-CTF-Probe/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                sock.sendall(http_req.encode())
                sock.settimeout(3.0)
                resp = sock.recv(16384)
                if resp.startswith(b"HTTP/"):
                    res["protocol"] = "http"
                    res["banner"] = resp.decode('utf-8', errors='replace')
            except Exception: pass
    sock.close()

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
            res["protocol"] = "https" if res["protocol"] == "http" or hint_scheme == "https" else "tls_raw"
            ssock.close()
        except Exception: pass
        finally:
            try: tls_sock.close()
            except Exception: pass

    full_text = res["banner"] or ""
    if res["protocol"] in ("http", "https") and full_text.startswith("HTTP/"):
        parts = full_text.split("\r\n\r\n", 1)
        headers = parts[0].split("\r\n")
        server_hdr = ""
        for h in headers[1:]:
            if h.lower().startswith("server:"):
                server_hdr = h.split(":", 1)[1].strip()
                break
        title = ""
        if len(parts) > 1:
            title_m = re.search(r'<title>(.*?)</title>', parts[1], re.IGNORECASE | re.DOTALL)
            if title_m: title = title_m.group(1).strip()
        res["http_info"] = {"status_line": headers[0] if headers else "", "server": server_hdr, "title": title}

    is_pow, pow_info = detect_pow(full_text)
    if is_pow:
        res["pow_detected"] = True
        res["pow_info"] = pow_info

    is_menu, menu_items = detect_interactive_menu(full_text)
    if is_menu:
        res["interactive_menu"] = True
        res["menu_items"] = menu_items

    if res["protocol"] == "https":
        res["suggested_command"] = f"curl -k -v https://{host}:{port}/"
    elif res["protocol"] == "http":
        res["suggested_command"] = f"curl -v http://{host}:{port}/"
    elif res["protocol"] == "tls_raw":
        res["suggested_command"] = f"openssl s_client -connect {host}:{port} -quiet"
    else:
        res["suggested_command"] = f"nc {host} {port}"
    return res

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    timeout = 10.0
    for a in sys.argv[2:]:
        if a.startswith("--timeout="):
            try: timeout = float(a.split("=", 1)[1])
            except ValueError: pass
    print(json.dumps(probe_target(target, timeout=timeout), indent=2, ensure_ascii=False))
`
