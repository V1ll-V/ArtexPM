import json, subprocess, shutil

def probe(name, group, args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=25)
        output = (p.stdout + p.stderr).strip()
        return dict(name=name, group=group, ready=p.returncode == 0, version=output[:1200], error="" if p.returncode == 0 else "exit " + str(p.returncode))
    except Exception as e:
        return dict(name=name, group=group, ready=False, version="", error=str(e))

items=[]
for name, group, args in [
    ("file","binary",["file","--version"]), ("binutils","binary",["readelf","--version"]),
    ("GDB","pwn",["gdb","--version"]), ("checksec","pwn",["/usr/bin/checksec","--version"]),
    ("ROPgadget","pwn",["/opt/ctf/pwn/bin/ROPgadget","--version"]),
    ("ropper","pwn",["/opt/ctf/pwn/bin/ropper","--version"]), ("one_gadget","pwn",["one_gadget","--version"]),
    ("pwninit","pwn",["pwninit","--version"]), ("radare2","reverse",["r2","-v"]),
    ("patchelf","pwn",["patchelf","--version"]), ("QEMU user","reverse",["qemu-x86_64","--version"]),
    ("UPX","reverse",["upx","--version"]),
    ("seccomp-tools","pwn",["seccomp-tools","--version"]),
    ("protoc","pwn",["protoc","--version"]),
    ("protobuf-c","pwn",["test","-f","/usr/include/protobuf-c/protobuf-c.h"]),
    ("ctf-pwn-triage","pwn",["python3","/opt/ctf/scripts/pwn_triage.py","--help"]),
    ("glibc-pool","pwn",["bash","-c","python3 -c 'import json; d=json.load(open(\"/opt/ctf/glibc/manifest.json\")); assert len(d)>=10; print(len(d), \"entries\")'"]),
    ("exiftool","forensics",["exiftool","-ver"]),
    ("tshark","forensics",["tshark","-v"]),
    ("tcpdump","forensics",["tcpdump","--version"]),
    ("ctf-pcap","forensics",["python3","/opt/ctf/scripts/pcap_analyze.py","--help"]),
    ("Ghidra / Java","reverse",["bash","-c","test -f /opt/ctf/ghidra_12.1.4_PUBLIC/Ghidra/application.properties && grep application.version /opt/ctf/ghidra_12.1.4_PUBLIC/Ghidra/application.properties && java -version"]),
]: items.append(probe(name,group,args))
distributions=dict(pwnlib="pwntools",keystone="keystone-engine",z3="z3-solver",claripy="angr",Crypto="pycryptodome",PIL="pillow",scapy="scapy",pyshark="pyshark")
for group, modules, python in [
    ("pwn",["pwnlib","capstone","unicorn","keystone","r2pipe","z3"],"/opt/ctf/pwn/bin/python"),
    ("crypto",["Crypto","gmpy2","sympy","numpy","PIL"],"/opt/ctf/pwn/bin/python"),
    ("forensics",["scapy","pyshark"],"/opt/ctf/pwn/bin/python"),
    ("reverse",["angr","claripy","capstone","unicorn","keystone","z3"],"/opt/ctf/re/bin/python")
]:
    for module in modules:
        imp="from angr import claripy" if module=="claripy" else f"import {module}"
        dist=distributions.get(module,module)
        items.append(probe(module,group,[python,"-c",f"{imp}; import importlib.metadata as m; print(m.version('{dist}'))"]))
print(json.dumps(items))
