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
    ("Ghidra / Java","reverse",["bash","-c","test -f /opt/ctf/ghidra_12.1.4_PUBLIC/Ghidra/application.properties && grep application.version /opt/ctf/ghidra_12.1.4_PUBLIC/Ghidra/application.properties && java -version"]),
]: items.append(probe(name,group,args))
distributions=dict(pwnlib="pwntools",keystone="keystone-engine",z3="z3-solver",claripy="angr")
for group, modules, python in [("pwn",["pwnlib","capstone","unicorn","keystone","r2pipe","z3"],"/opt/ctf/pwn/bin/python"),("reverse",["angr","claripy","capstone","unicorn","keystone","z3"],"/opt/ctf/re/bin/python")]:
    for module in modules:
        imp="from angr import claripy" if module=="claripy" else f"import {module}"
        dist=distributions.get(module,module)
        items.append(probe(module,group,[python,"-c",f"{imp}; import importlib.metadata as m; print(m.version('{dist}'))"]))
print(json.dumps(items))
