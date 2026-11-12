package ctf

const PcapAnalyzeScript = `import argparse, hashlib, json, os, re, shutil, subprocess, sys

FLAG_PATTERNS = [
    re.compile(r'(flag\{[^\}\n\r]+\})', re.IGNORECASE),
    re.compile(r'(ctf\{[^\}\n\r]+\})', re.IGNORECASE),
    re.compile(r'([A-Za-z0-9_\-]+flag\{[^\}\n\r]+\})', re.IGNORECASE),
    re.compile(r'([A-Za-z0-9_\-]+CTF\{[^\}\n\r]+\})', re.IGNORECASE),
]

def find_flags(text):
    candidates = []
    if not text:
        return candidates
    for pat in FLAG_PATTERNS:
        for match in pat.findall(text):
            m = match.strip()
            if m and m not in candidates:
                candidates.append(m)
    return candidates

def run_cmd(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s: {' '.join(cmd)}"
    except Exception as e:
        return -1, "", str(e)

def analyze_summary(pcap_path):
    result = {"action": "summary", "pcap": pcap_path, "metadata": {}, "protocol_hierarchy": "", "ip_conversations": []}
    rc, stdout, _ = run_cmd(["capinfos", "-c", "-u", "-d", "-s", "-y", "-k", pcap_path])
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                result["metadata"][k.strip()] = v.strip()
    rc, stdout, _ = run_cmd(["tshark", "-r", pcap_path, "-q", "-z", "io,phs"])
    if rc == 0 and stdout:
        result["protocol_hierarchy"] = stdout
    rc, stdout, _ = run_cmd(["tshark", "-r", pcap_path, "-q", "-z", "conv,ip"])
    if rc == 0 and stdout:
        conv_lines = []
        capture = False
        for line in stdout.splitlines():
            if "IPv4 Conversations" in line or "IPv6 Conversations" in line:
                capture = True
                continue
            if capture and line.startswith("==="):
                continue
            if capture and line.strip():
                conv_lines.append(line)
        result["ip_conversations"] = conv_lines[:30]
    return result

def analyze_http(pcap_path, display_filter=None):
    filt = "http.request or http.response"
    if display_filter:
        filt = f"({filt}) and ({display_filter})"
    cmd = [
        "tshark", "-r", pcap_path, "-Y", filt,
        "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
        "-e", "http.request.method", "-e", "http.host",
        "-e", "http.request.uri", "-e", "http.response.code",
        "-e", "http.content_type"
    ]
    rc, stdout, _ = run_cmd(cmd)
    items = []
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 6:
                frame, src, dst, method, host, uri = parts[:6]
                code = parts[6] if len(parts) > 6 else ""
                ctype = parts[7] if len(parts) > 7 else ""
                items.append({
                    "frame": frame, "src": src, "dst": dst, "method": method,
                    "host": host, "uri": uri, "code": code, "content_type": ctype,
                })
    auth_cmd = [
        "tshark", "-r", pcap_path, "-Y", "http.authorization or http.cookie",
        "-T", "fields",
        "-e", "frame.number", "-e", "http.authorization", "-e", "http.cookie"
    ]
    _, auth_out, _ = run_cmd(auth_cmd)
    auths = []
    if auth_out:
        for line in auth_out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and any(parts[1:]):
                auths.append({"frame": parts[0], "auth": parts[1] if len(parts) > 1 else "", "cookie": parts[2] if len(parts) > 2 else ""})
    flags = find_flags(stdout + "\n" + (auth_out or ""))
    return {
        "action": "http", "pcap": pcap_path, "total_http_packets": len(items),
        "requests": items[:100], "credentials_and_cookies": auths[:30],
        "discovered_flags": flags
    }

def analyze_dns(pcap_path, display_filter=None):
    filt = "dns"
    if display_filter:
        filt = f"({filt}) and ({display_filter})"
    cmd = [
        "tshark", "-r", pcap_path, "-Y", filt,
        "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
        "-e", "dns.qry.name", "-e", "dns.qry.type", "-e", "dns.a", "-e", "dns.txt"
    ]
    rc, stdout, _ = run_cmd(cmd)
    queries, domain_counts, tunneling_suspects = [], {}, []
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 4 and parts[3]:
                frame, src, dst, qname = parts[:4]
                qtype = parts[4] if len(parts) > 4 else ""
                ans_a = parts[5] if len(parts) > 5 else ""
                ans_txt = parts[6] if len(parts) > 6 else ""
                queries.append({
                    "frame": frame, "src": src, "dst": dst, "query": qname, "type": qtype,
                    "answer_a": ans_a, "answer_txt": ans_txt
                })
                base = ".".join(qname.split(".")[-3:]) if len(qname.split(".")) >= 3 else qname
                domain_counts[base] = domain_counts.get(base, 0) + 1
                prefix = qname.split(".")[0]
                if len(prefix) > 20 or re.match(r'^[0-9a-fA-F]{16,}$', prefix) or re.match(r'^[A-Za-z0-9+/=]{20,}$', prefix):
                    if prefix not in tunneling_suspects:
                        tunneling_suspects.append(prefix)
    flags = find_flags(stdout)
    return {
        "action": "dns", "pcap": pcap_path, "total_queries": len(queries),
        "queries": queries[:100],
        "top_domains": sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:15],
        "tunneling_exfiltration_suspects": tunneling_suspects[:30],
        "discovered_flags": flags
    }

def analyze_streams(pcap_path):
    rc, stdout, _ = run_cmd(["tshark", "-r", pcap_path, "-q", "-z", "conv,tcp"])
    streams = []
    if rc == 0 and stdout:
        capture = False
        for line in stdout.splitlines():
            if "TCP Conversations" in line:
                capture = True
                continue
            if capture and line.startswith("==="):
                continue
            if capture and line.strip():
                streams.append(line)
    return {"action": "streams", "pcap": pcap_path, "tcp_conversations": streams[:50]}

def analyze_stream_follow(pcap_path, stream_id):
    rc, stdout, _ = run_cmd(["tshark", "-r", pcap_path, "-qz", f"follow,tcp,ascii,{stream_id}"])
    flags = find_flags(stdout)
    return {"action": "stream", "pcap": pcap_path, "stream_id": stream_id, "transcript": stdout, "discovered_flags": flags}

def analyze_export(pcap_path, export_dir="/work/exported_pcap"):
    os.makedirs(export_dir, exist_ok=True)
    run_cmd(["tshark", "-r", pcap_path, "--export-objects", f"http,{export_dir}"])
    extracted_files, all_flags = [], []
    if os.path.exists(export_dir):
        for fname in os.listdir(export_dir):
            fpath = os.path.join(export_dir, fname)
            if os.path.isfile(fpath):
                size = os.path.getsize(fpath)
                with open(fpath, "rb") as f:
                    content = f.read()
                    sha = hashlib.sha256(content).hexdigest()
                    try:
                        text_peek = content.decode("utf-8", errors="ignore")
                        all_flags.extend(find_flags(text_peek))
                    except Exception:
                        pass
                extracted_files.append({"name": fname, "path": fpath, "size_bytes": size, "sha256": sha})
    return {
        "action": "export", "pcap": pcap_path, "export_directory": export_dir,
        "total_extracted_files": len(extracted_files), "files": extracted_files,
        "discovered_flags": list(set(all_flags))
    }

def analyze_search(pcap_path, pattern):
    filt = f'frame contains "{pattern}"'
    cmd = [
        "tshark", "-r", pcap_path, "-Y", filt,
        "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
        "-e", "_ws.col.Protocol", "-e", "_ws.col.Info"
    ]
    rc, stdout, _ = run_cmd(cmd)
    matches = []
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 4:
                matches.append({"frame": parts[0], "src": parts[1], "dst": parts[2], "protocol": parts[3], "info": parts[4] if len(parts) > 4 else ""})
    strings_rc, strings_out, _ = run_cmd(["strings", pcap_path])
    matched_lines = []
    if strings_rc == 0 and strings_out:
        for line in strings_out.splitlines():
            if pattern.lower() in line.lower():
                matched_lines.append(line.strip())
    flags = find_flags(strings_out) if strings_rc == 0 else []
    return {
        "action": "search", "pcap": pcap_path, "pattern": pattern,
        "matched_frames_count": len(matches), "matched_frames": matches[:30],
        "string_matches": matched_lines[:20], "discovered_flags": flags
    }

def analyze_icmp(pcap_path):
    cmd = [
        "tshark", "-r", pcap_path, "-Y", "icmp",
        "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
        "-e", "icmp.type", "-e", "data.text", "-e", "data.data"
    ]
    rc, stdout, _ = run_cmd(cmd)
    records, extracted_text = [], []
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 4:
                frame, src, dst, itype = parts[:4]
                dtext = parts[4] if len(parts) > 4 else ""
                dhex = parts[5] if len(parts) > 5 else ""
                if dtext:
                    extracted_text.append(dtext)
                elif dhex:
                    try:
                        extracted_text.append(bytes.fromhex(dhex).decode("utf-8", errors="ignore"))
                    except Exception:
                        pass
                records.append({"frame": frame, "src": src, "dst": dst, "type": itype, "text": dtext, "hex": dhex})
    full_text = "\n".join(extracted_text)
    return {
        "action": "icmp", "pcap": pcap_path, "total_icmp_packets": len(records),
        "records": records[:50], "extracted_payload_text": full_text[:2000],
        "discovered_flags": find_flags(full_text)
    }

def main():
    parser = argparse.ArgumentParser(description="CTF PCAP / Traffic Analysis Tool")
    parser.add_argument("pcap", help="Path to PCAP or PCAPNG file")
    parser.add_argument("--mode", choices=["summary", "http", "dns", "streams", "stream", "export", "search", "icmp"], default="summary")
    parser.add_argument("--stream-id", type=int, default=0)
    parser.add_argument("--filter", default="")
    parser.add_argument("--search", default="flag")
    parser.add_argument("--export-dir", default="/work/exported_pcap")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not os.path.isfile(args.pcap):
        sys.stderr.write(f"Error: file not found: {args.pcap}\n")
        sys.exit(1)
    m = args.mode
    if m == "summary": res = analyze_summary(args.pcap)
    elif m == "http": res = analyze_http(args.pcap, args.filter)
    elif m == "dns": res = analyze_dns(args.pcap, args.filter)
    elif m == "streams": res = analyze_streams(args.pcap)
    elif m == "stream": res = analyze_stream_follow(args.pcap, args.stream_id)
    elif m == "export": res = analyze_export(args.pcap, args.export_dir)
    elif m == "search": res = analyze_search(args.pcap, args.search)
    elif m == "icmp": res = analyze_icmp(args.pcap)
    else: res = {"error": f"Unknown mode: {m}"}
    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        B = chr(96)
        B3 = chr(96) * 3
        print(f"### PCAP 分析结果 [{m.upper()}] — {os.path.basename(args.pcap)}")
        if res.get("discovered_flags"):
            print("\n> [!IMPORTANT]\n> **捕获候选 Flag**：" + ", ".join(f"{B}{x}{B}" for x in res["discovered_flags"]) + "\n")
        if m == "summary":
            if res.get("metadata"):
                print("#### 文件元数据")
                for k, v in res["metadata"].items(): print(f"- **{k}**: {v}")
            if res.get("protocol_hierarchy"):
                print(f"\n#### 协议层级分布 (Protocol Hierarchy)\n{B3}text\n" + res["protocol_hierarchy"] + f"\n{B3}")
            if res.get("ip_conversations"):
                print(f"\n#### 主要 IP 会话流\n{B3}text\n" + "\n".join(res["ip_conversations"]) + f"\n{B3}")
        elif m == "http":
            print(f"- 捕获 HTTP 请求/响应总数：{res.get('total_http_packets', 0)}")
            if res.get("credentials_and_cookies"):
                print("\n#### 认证信息与 Cookie 凭据")
                for c in res["credentials_and_cookies"]:
                    print(f"- Frame #{c['frame']}: Auth {B}{c['auth']}{B} | Cookie {B}{c['cookie']}{B}")
            if res.get("requests"):
                print("\n#### HTTP 请求明细 (前 50 条)")
                print("| Frame | Method | Host | URI | Code | Content-Type |\n| :--- | :--- | :--- | :--- | :--- | :--- |")
                for r in res["requests"][:50]:
                    print(f"| {r['frame']} | {r['method']} | {r['host']} | {B}{r['uri']}{B} | {r['code']} | {r['content_type']} |")
        elif m == "dns":
            print(f"- 捕获 DNS 解析请求数：{res.get('total_queries', 0)}")
            if res.get("tunneling_exfiltration_suspects"):
                print("\n#### 异常长子域名 (潜在 DNS 隐蔽隧道 / 隐写外发)")
                for s in res["tunneling_exfiltration_suspects"]: print(f"- {B}{s}{B}")
            if res.get("top_domains"):
                print("\n#### 核心解析域名排行")
                for d, count in res["top_domains"]: print(f"- {B}{d}{B}: {count} 次请求")
        elif m == "streams":
            print(f"#### TCP 会话流列表 (可使用 --mode=stream --stream-id=<ID> 跟踪详情)\n{B3}text\n" + "\n".join(res.get("tcp_conversations", [])) + f"\n{B3}")
        elif m == "stream":
            print(f"#### TCP 流 #{args.stream_id} 完整跟踪对话\n{B3}text\n" + res.get("transcript", "") + f"\n{B3}")
        elif m == "export":
            print(f"- 成功导出文件总数：{res.get('total_extracted_files', 0)}（保存至 {B}{res.get('export_directory')}{B}）")
            if res.get("files"):
                print("\n| 文件名 | 大小 | SHA-256 |\n| :--- | :--- | :--- |")
                for f in res["files"]: print(f"| {B}{f['name']}{B} | {f['size_bytes']} B | {B}{f['sha256'][:16]}...{B} |")
        elif m == "search":
            print(f"- 关键字 {B}{args.search}{B} 匹配数据包数：{res.get('matched_frames_count', 0)}")
            if res.get("string_matches"):
                print(f"\n#### 字符串命中行\n{B3}text\n" + "\n".join(res["string_matches"]) + f"\n{B3}")
        elif m == "icmp":
            print(f"- 捕获 ICMP 包数：{res.get('total_icmp_packets', 0)}")
            if res.get("extracted_payload_text"):
                print(f"\n#### 提取的 ICMP 有效载荷文本\n{B3}text\n" + res["extracted_payload_text"] + f"\n{B3}")

if __name__ == "__main__":
    main()
`
