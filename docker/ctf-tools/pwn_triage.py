#!/usr/bin/env python3
"""
CTF Pwn One-Shot Triage & Local Environment Helper (ctf_pwn_triage)
Collects binary file/arch, checksec, key imports, framework signatures
(protobuf-c, seccomp, C++/Go/Rust, heap), libc GNU version + BuildID,
and matches/patches against /opt/ctf/glibc offline pool when available.
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess


def run_cmd(args, timeout=15):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as e:
        return -1, "", str(e)


def parse_checksec(raw):
    out = {}
    for line in raw.splitlines():
        s = line.strip()
        for key, field in (
            ("RELRO:", "relro"),
            ("Stack:", "canary"),
            ("NX:", "nx"),
            ("PIE:", "pie"),
        ):
            if key in s:
                out[field] = s.split(key, 1)[1].strip()
    if raw:
        out["raw"] = raw
    return out


def detect_libc_meta(libc_path):
    meta = {"path": libc_path, "gnu_version": "", "build_id": "", "arch": ""}
    if not libc_path or not os.path.isfile(libc_path):
        return meta
    _, f_out, _ = run_cmd(["file", "-b", libc_path])
    meta["arch"] = "i386" if ("32-bit" in f_out or "80386" in f_out) else "amd64" if "64-bit" in f_out else ""
    _, r_out, _ = run_cmd(["readelf", "-n", libc_path])
    m_bid = re.search(r"Build ID:\s*([0-9a-fA-F]+)", r_out)
    if m_bid:
        meta["build_id"] = m_bid.group(1).lower()
    try:
        with open(libc_path, "rb") as f:
            data = f.read()
        m_gnu = re.search(rb"GNU C Library \([^)]+\) [^\r\n\x00]{1,120}", data)
        if m_gnu:
            meta["gnu_version"] = m_gnu.group(0).decode("utf-8", errors="replace")
        if not meta["gnu_version"]:
            m_ver = re.search(rb"GLIBC_\d+\.\d+(?:\.\d+)?", data)
            if m_ver:
                meta["gnu_version"] = m_ver.group(0).decode("utf-8", errors="replace")
    except Exception:
        pass
    return meta


def find_glibc_match(libc_meta, arch):
    manifest_path = "/opt/ctf/glibc/manifest.json"
    if not os.path.isfile(manifest_path):
        return None
    try:
        entries = json.load(open(manifest_path, "r", encoding="utf-8"))
    except Exception:
        return None
    target_bid = (libc_meta.get("build_id") or "").lower()
    gnu_str = (libc_meta.get("gnu_version") or "").lower()
    # Extract Ubuntu version token e.g. 2.35-0ubuntu3.7 or minor 2.35
    m_ubuntu = re.search(r"(\d+\.\d+-[0-9a-zA-Z.~+]+)", gnu_str)
    exact_ver = m_ubuntu.group(1) if m_ubuntu else ""
    m_minor = re.search(r"release version (\d+\.\d+)", gnu_str)
    minor_ver = m_minor.group(1) if m_minor else ""
    if not minor_ver and exact_ver:
        minor_ver = exact_ver.split("-", 1)[0]

    candidates = [e for e in entries if (not arch or e.get("arch") == arch)]
    for e in candidates:
        if target_bid and e.get("libc_build_id", "").lower() == target_bid:
            return {**e, "match_type": "exact_build_id"}
    for e in candidates:
        if exact_ver and exact_ver in (e.get("version", "").lower()):
            return {**e, "match_type": "exact_version"}
    for e in candidates:
        if minor_ver and e.get("minor") == minor_ver:
            return {**e, "match_type": "same_minor_fallback"}
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--libc", default="")
    ap.add_argument("--work-dir", default="/work")
    ap.add_argument("--patch", action="store_true")
    args = ap.parse_args()

    bin_path = args.path
    if not os.path.isfile(bin_path):
        print(json.dumps({"error": f"file not found: {bin_path}"}, ensure_ascii=False))
        return

    res = {
        "input_path": bin_path,
        "work_copy": None,
        "patched_binary": None,
        "file": "",
        "arch": "",
        "stripped": False,
        "checksec": {},
        "imports_highlight": [],
        "framework_hints": [],
        "libc": None,
        "offline_glibc_match": None,
        "next_steps": [],
    }

    _, f_out, _ = run_cmd(["file", "-b", bin_path])
    res["file"] = f_out
    res["stripped"] = "stripped" in f_out and "not stripped" not in f_out
    if "64-bit" in f_out or "x86-64" in f_out:
        res["arch"] = "amd64"
    elif "32-bit" in f_out or "80386" in f_out:
        res["arch"] = "i386"

    _, chk_out, chk_err = run_cmd(["/opt/ctf/pwn/bin/pwn", "checksec", bin_path])
    res["checksec"] = parse_checksec(chk_out or chk_err)

    _, sym_out, _ = run_cmd(["nm", "-D", bin_path])
    if not sym_out:
        _, sym_out, _ = run_cmd(["readelf", "--dyn-syms", "-W", bin_path])
    try:
        with open(bin_path, "rb") as f:
            raw_bin = f.read(4 << 20)
    except Exception:
        raw_bin = b""

    interesting = [
        "system", "execve", "open", "openat", "read", "write", "gets", "fgets",
        "strcpy", "strcat", "strlen", "sprintf", "printf", "scanf", "mmap",
        "mprotect", "prctl", "seccomp", "malloc", "calloc", "realloc", "free",
        "protobuf_c_message_unpack", "protobuf_c_message_get_packed_size",
    ]
    found_imports = []
    for sym in interesting:
        if sym in sym_out or sym.encode() in raw_bin:
            found_imports.append(sym)
    res["imports_highlight"] = found_imports

    hints = []
    if b"protobuf_c_" in raw_bin or b".pb-c.c" in raw_bin or "protobuf" in sym_out.lower():
        has_protoc = bool(shutil.which("protoc"))
        has_hdr = os.path.isfile("/usr/include/protobuf-c/protobuf-c.h")
        hints.append(f"protobuf-c 协议解析 (protoc={has_protoc}, protobuf-c.h={has_hdr})")
    if b"seccomp" in raw_bin or "prctl" in found_imports or "seccomp" in sym_out.lower():
        hints.append("存在 seccomp/prctl 沙箱过滤，需使用 seccomp-tools dump 检查禁用系统调用")
    if any(k in found_imports for k in ("malloc", "free", "calloc", "realloc")):
        hints.append("包含动态堆分配操作 (malloc/free)")
    if res["stripped"]:
        hints.append("二进制已去符号 (stripped)")
    res["framework_hints"] = hints

    work_dir = args.work_dir or "/work"
    os.makedirs(work_dir, exist_ok=True)
    base_name = os.path.basename(bin_path)
    if base_name == "original":
        base_name = "chall"
    work_bin = os.path.join(work_dir, base_name)
    if os.path.abspath(bin_path) != os.path.abspath(work_bin):
        shutil.copy2(bin_path, work_bin)
    os.chmod(work_bin, 0o755)
    res["work_copy"] = work_bin

    libc_path = args.libc
    if not libc_path:
        search_dirs = list({os.path.dirname(os.path.abspath(bin_path)), os.path.abspath(work_dir)})
        for d in search_dirs:
            for pat in ("libc.so*", "libc-*.so*"):
                hits = sorted(glob.glob(os.path.join(d, pat)))
                if hits:
                    libc_path = hits[0]
                    break
            if libc_path:
                break

    if libc_path and os.path.isfile(libc_path):
        work_libc = os.path.join(work_dir, "libc.so.6")
        if os.path.abspath(libc_path) != os.path.abspath(work_libc):
            shutil.copy2(libc_path, work_libc)
        os.chmod(work_libc, 0o755)
        meta = detect_libc_meta(work_libc)
        res["libc"] = meta
        match = find_glibc_match(meta, res["arch"])
        res["offline_glibc_match"] = match
        if args.patch and match and os.path.isfile(match.get("ld_path", "")) and shutil.which("patchelf"):
            ld_name = os.path.basename(match["ld_path"])
            work_ld = os.path.join(work_dir, ld_name)
            shutil.copy2(match["ld_path"], work_ld)
            os.chmod(work_ld, 0o755)
            patched = work_bin + "_patched"
            shutil.copy2(work_bin, patched)
            os.chmod(patched, 0o755)
            rc1, _, err1 = run_cmd(["patchelf", "--set-interpreter", work_ld, patched])
            rc2, _, err2 = run_cmd(["patchelf", "--set-rpath", work_dir, patched])
            if rc1 == 0 and rc2 == 0:
                res["patched_binary"] = patched
            else:
                res["patch_error"] = (err1 + " " + err2).strip()

    if res["stripped"]:
        res["next_steps"].append(f"优先调用 ctf_decompile(path={work_bin!r}, limit=20) 提取 Ghidra 反编译伪代码，避免在 Bash 用 objdump 盲读汇编。")
    if res["libc"] and not res["patched_binary"]:
        if res["offline_glibc_match"]:
            res["next_steps"].append("已命中本地 /opt/ctf/glibc 缓存，传入 patch=true 或用 patchelf 直接绑定本地 ld。")
        else:
            res["next_steps"].append("本地缓存未收录精确 BuildID；如需匹配调试符号再按需下载对应 libc6 包，或确认系统当前 glibc 小版本是否 ABI 兼容。")

    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
