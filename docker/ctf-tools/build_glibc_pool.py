#!/usr/bin/env python3
"""
Build an offline curated Ubuntu LTS glibc/ld pool in /opt/ctf/glibc
with a manifest.json index used by /opt/ctf/scripts/pwn_triage.py.
Keeps only libc.so.6, dynamic linker (ld-linux*), and libpthread.so.0 (when distinct)
to minimize container image footprint.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request

GLIBC_MIRRORS = (
    "https://mirrors.cloud.tencent.com/ubuntu/pool/main/g/glibc/",
    "https://mirrors.aliyun.com/ubuntu/pool/main/g/glibc/",
    "https://mirrors.ustc.edu.cn/ubuntu/pool/main/g/glibc/",
    "https://mirrors.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/",
    "http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/",
)

# Verified Ubuntu LTS packages on mirrors.ustc.edu.cn / archive.ubuntu.com
PACKAGES = (
    ("2.23-0ubuntu11.3", "2.23", "amd64", "libc6_2.23-0ubuntu11.3_amd64.deb"),
    ("2.23-0ubuntu11.3", "2.23", "i386", "libc6_2.23-0ubuntu11.3_i386.deb"),
    ("2.27-3ubuntu1.6", "2.27", "amd64", "libc6_2.27-3ubuntu1.6_amd64.deb"),
    ("2.27-3ubuntu1.6", "2.27", "i386", "libc6_2.27-3ubuntu1.6_i386.deb"),
    ("2.31-0ubuntu9.18", "2.31", "amd64", "libc6_2.31-0ubuntu9.18_amd64.deb"),
    ("2.31-0ubuntu9.18", "2.31", "i386", "libc6_2.31-0ubuntu9.18_i386.deb"),
    ("2.35-0ubuntu3", "2.35", "amd64", "libc6_2.35-0ubuntu3_amd64.deb"),
    ("2.35-0ubuntu3.18", "2.35", "amd64", "libc6_2.35-0ubuntu3.18_amd64.deb"),
    ("2.35-0ubuntu3.18", "2.35", "i386", "libc6_2.35-0ubuntu3.18_i386.deb"),
    ("2.39-0ubuntu8", "2.39", "amd64", "libc6_2.39-0ubuntu8_amd64.deb"),
    ("2.39-0ubuntu8.12", "2.39", "amd64", "libc6_2.39-0ubuntu8.12_amd64.deb"),
    ("2.39-0ubuntu8.12", "2.39", "i386", "libc6_2.39-0ubuntu8.12_i386.deb"),
)

DEST_ROOT = "/opt/ctf/glibc"


def resolve_in_root(extract_root, path):
    """Resolve symlinks strictly inside extract_root without escaping to host root."""
    cur = path
    for _ in range(16):
        if not os.path.islink(cur):
            return cur
        target = os.readlink(cur)
        if target.startswith("/"):
            cur = os.path.join(extract_root, target.lstrip("/"))
        else:
            cur = os.path.normpath(os.path.join(os.path.dirname(cur), target))
    return cur


def find_first_matching(extract_root, candidates):
    for rel in candidates:
        p = os.path.join(extract_root, rel.lstrip("/"))
        if os.path.lexists(p):
            resolved = resolve_in_root(extract_root, p)
            if os.path.isfile(resolved):
                return resolved
    return ""


def read_build_id(elf_path):
    res = subprocess.run(
        ["readelf", "-n", elf_path],
        capture_output=True,
        text=True,
        check=False,
    )
    m = re.search(r"Build ID:\s*([0-9a-fA-F]+)", res.stdout or "")
    return m.group(1).lower() if m else ""


def download_deb(deb_name, dest_file):
    last_err = None
    for attempt in range(2):
        for base in GLIBC_MIRRORS:
            url = base + deb_name
            tmp_part = dest_file + ".part"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "artex-ctf-tools/1.0"})
                with urllib.request.urlopen(req, timeout=180) as resp, open(tmp_part, "wb") as out:
                    shutil.copyfileobj(resp, out)
                if os.path.getsize(tmp_part) > 1024:
                    os.replace(tmp_part, dest_file)
                    return
            except Exception as exc:
                last_err = exc
                if os.path.exists(tmp_part):
                    os.remove(tmp_part)
        time.sleep(1 + attempt)
    raise RuntimeError(f"failed to download {deb_name}: {last_err}")


def find_by_walk(extract_root, names):
    """Fallback walk inside extract_root to locate real ELF files across usr-merge layouts."""
    for base_name in names:
        for dirpath, _, filenames in os.walk(extract_root):
            if base_name in filenames:
                resolved = resolve_in_root(extract_root, os.path.join(dirpath, base_name))
                if os.path.isfile(resolved):
                    return resolved
    return ""


def process_one(pkg, tmpdir):
    version, minor, arch, deb_name = pkg
    deb_path = os.path.join(tmpdir, deb_name)
    extract_dir = os.path.join(tmpdir, f"extract_{version}_{arch}")
    download_deb(deb_name, deb_path)
    os.makedirs(extract_dir, exist_ok=True)
    subprocess.run(["dpkg-deb", "-x", deb_path, extract_dir], check=True)
    os.remove(deb_path)

    if arch == "amd64":
        libdirs = ("lib/x86_64-linux-gnu", "usr/lib/x86_64-linux-gnu")
        ld_name = "ld-linux-x86-64.so.2"
        ld_candidates = [
            "lib64/ld-linux-x86-64.so.2",
            "usr/lib64/ld-linux-x86-64.so.2",
            *(f"{d}/ld-linux-x86-64.so.2" for d in libdirs),
            *(f"{d}/ld-{minor}.so" for d in libdirs),
        ]
        ld_walk_names = (ld_name, f"ld-{minor}.so")
    else:
        libdirs = ("lib/i386-linux-gnu", "usr/lib/i386-linux-gnu")
        ld_name = "ld-linux.so.2"
        ld_candidates = [
            "lib/ld-linux.so.2",
            "usr/lib/ld-linux.so.2",
            *(f"{d}/ld-linux.so.2" for d in libdirs),
            *(f"{d}/ld-{minor}.so" for d in libdirs),
        ]
        ld_walk_names = (ld_name, f"ld-{minor}.so")

    libc_candidates = [*(f"{d}/libc.so.6" for d in libdirs), *(f"{d}/libc-{minor}.so" for d in libdirs)]
    pthread_candidates = [*(f"{d}/libpthread.so.0" for d in libdirs), *(f"{d}/libpthread-{minor}.so" for d in libdirs)]

    libc_src = find_first_matching(extract_dir, libc_candidates) or find_by_walk(extract_dir, ("libc.so.6", f"libc-{minor}.so"))
    ld_src = find_first_matching(extract_dir, ld_candidates) or find_by_walk(extract_dir, ld_walk_names)
    if not libc_src or not ld_src:
        raise RuntimeError(f"missing libc/ld in {deb_name} (libc={libc_src}, ld={ld_src})")

    tag_dir = os.path.join(DEST_ROOT, f"{version}_{arch}")
    os.makedirs(tag_dir, mode=0o755, exist_ok=True)
    libc_dst = os.path.join(tag_dir, "libc.so.6")
    ld_dst = os.path.join(tag_dir, ld_name)
    shutil.copy2(libc_src, libc_dst)
    shutil.copy2(ld_src, ld_dst)
    os.chmod(libc_dst, 0o755)
    os.chmod(ld_dst, 0o755)

    pthread_src = find_first_matching(extract_dir, pthread_candidates) or find_by_walk(extract_dir, ("libpthread.so.0", f"libpthread-{minor}.so"))
    if pthread_src and os.path.abspath(pthread_src) != os.path.abspath(libc_src):
        pthread_dst = os.path.join(tag_dir, "libpthread.so.0")
        shutil.copy2(pthread_src, pthread_dst)
        os.chmod(pthread_dst, 0o755)

    shutil.rmtree(extract_dir, ignore_errors=True)
    print(f"[ok] {version} ({arch})", flush=True)
    return {
        "version": version,
        "minor": minor,
        "arch": arch,
        "libc_build_id": read_build_id(libc_dst),
        "libc_path": libc_dst,
        "ld_path": ld_dst,
    }


def main():
    os.makedirs(DEST_ROOT, mode=0o755, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="glibc_pool_") as tmpdir:
        with ThreadPoolExecutor(max_workers=4) as pool:
            manifest = list(pool.map(lambda pkg: process_one(pkg, tmpdir), PACKAGES))

    manifest_path = os.path.join(DEST_ROOT, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    os.chmod(manifest_path, 0o644)
    print(f"built {len(manifest)} offline glibc entries -> {manifest_path}")


if __name__ == "__main__":
    main()
