#!/usr/bin/env python3
"""
kernel_driver_analyze.py  v4.0
Windows kernel driver vulnerability analysis engine — fully self-contained.

Usage:
    python3 kernel_driver_analyze.py <driver.sys> [options]
    python3 kernel_driver_analyze.py --diff old.sys new.sys [options]
    python3 kernel_driver_analyze.py --dir /path/to/drivers/ [options]

Options:
    --force       Re-generate disassembly even if cached
    --out <file>  JSON output path  (default: <driver>_findings.json)
    --diff <old>  Patch-diff mode: compare old vs new build
    --dir  <dir>  Batch mode: analyze every .sys in directory
    --no-html     Skip HTML report
    --no-poc      Skip PoC skeleton
    --no-windbg   Skip WinDbg script
    --no-ghidra   Skip Ghidra bookmark script
    --color       Force ANSI colour even when not a tty
"""
import struct, sys, re, json, os, time, subprocess, shutil, threading, csv, glob, hashlib
from collections import defaultdict
from pathlib import Path
from datetime import datetime

# ── Colour helpers ────────────────────────────────────────────────────────
USE_COLOR = sys.stdout.isatty() or "--color" in sys.argv
def C(c,s): return f"\033[{c}m{s}\033[0m" if USE_COLOR else s
RED    = lambda s: C("91",s); YELLOW = lambda s: C("93",s)
GREEN  = lambda s: C("92",s); CYAN   = lambda s: C("96",s)
BOLD   = lambda s: C("1",s);  DIM    = lambda s: C("2",s)

# ── Argument parsing ──────────────────────────────────────────────────────
_args        = sys.argv[1:]
FORCE_DISASM = "--force"     in _args
SKIP_HTML    = "--no-html"   in _args
SKIP_POC     = "--no-poc"    in _args
SKIP_WINDBG  = "--no-windbg" in _args
SKIP_GHIDRA  = "--no-ghidra" in _args

def _flag_val(flag):
    try: i = _args.index(flag); return _args[i+1]
    except (ValueError, IndexError): return None

JSON_OUT  = _flag_val("--out")
DIFF_OLD  = _flag_val("--diff")
BATCH_DIR = _flag_val("--dir")

SYS_FILE = next(
    (a for a in _args if not a.startswith("--") and a not in (JSON_OUT, DIFF_OLD, BATCH_DIR)),
    None
)

if not _args or (not SYS_FILE and not BATCH_DIR):
    print(__doc__); sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════
# SINGLE-DRIVER ANALYSIS PIPELINE
# ══════════════════════════════════════════════════════════════════════════
def run_single(SYS_FILE):
    if not os.path.isfile(SYS_FILE):
        print(RED(f"[!] Not found: {SYS_FILE}")); return None

    stem        = Path(SYS_FILE).stem
    DISASM_FILE = f"{stem}_disasm.txt"
    json_out    = JSON_OUT or f"{stem}_findings.json"

    print(BOLD(f"\n{'='*70}"))
    print(BOLD( "  Windows Kernel Driver Analyzer v4.0"))
    print(BOLD(f"  Target  : {SYS_FILE}"))
    print(BOLD(f"  Disasm  : {DISASM_FILE}"))
    print(BOLD(f"  Report  : {json_out}"))
    print(BOLD(f"{'='*70}\n"))

    DATA = open(SYS_FILE, "rb").read()
    t0   = time.time()

    # ── PE helpers ────────────────────────────────────────────────────────
    def u8(o):  return DATA[o]
    def u16(o): return struct.unpack_from("<H", DATA, o)[0]
    def u32(o): return struct.unpack_from("<I", DATA, o)[0]
    def u64(o): return struct.unpack_from("<Q", DATA, o)[0]

    if DATA[:2] != b"MZ": print(RED("[!] Not a PE")); return None
    pe = u32(0x3c)
    if DATA[pe:pe+4] != b"PE\0\0": print(RED("[!] Bad PE sig")); return None
    ns      = u16(pe+6)
    opt_off = pe + 24
    if u16(opt_off) != 0x20b: print(RED("[!] Not PE32+ (x64)")); return None

    dll_chars  = u16(opt_off+70)
    image_base = u64(opt_off+24)
    ep_rva     = u32(opt_off+16)
    ASLR  = bool(dll_chars & 0x0040)
    NX    = bool(dll_chars & 0x0100)
    CFG   = bool(dll_chars & 0x4000)
    FINT  = bool(dll_chars & 0x0080)

    SECTS = []
    for i in range(ns):
        o = opt_off + 240 + i*40
        SECTS.append(dict(
            name   = DATA[o:o+8].rstrip(b"\x00").decode(errors="replace"),
            vrva   = u32(o+12), vsize = u32(o+8),
            rawptr = u32(o+20), rawsz = u32(o+16),
        ))

    def rva2off(rva):
        for s in SECTS:
            if s["vrva"] <= rva < s["vrva"]+s["vsize"]:
                return s["rawptr"] + (rva - s["vrva"])
        return None

    # ── Version extraction ────────────────────────────────────────────────
    def extract_version():
        try:
            rsrc = next((s for s in SECTS if s["name"]==".rsrc"), None)
            if not rsrc: return "unknown"
            b = rsrc["rawptr"]
            def cnt(o): return u16(b+o+12)+u16(b+o+14)
            def entry(o,i): return struct.unpack_from("<II", DATA, b+o+16+i*8)
            for i in range(cnt(0)):
                nid, off = entry(0, i)
                if nid == 16:
                    l2 = off & 0x7FFFFFFF
                    if cnt(l2):
                        _, l3r = entry(l2, 0); l3 = l3r & 0x7FFFFFFF
                        if cnt(l3):
                            _, der = entry(l3, 0); de = der & 0x7FFFFFFF
                            raw = rva2off(u32(b+de))
                            if raw is None: return "unknown"
                            ffi = raw + 40
                            if DATA[ffi:ffi+4] != b"\xbd\x04\xef\xfe": return "unknown"
                            ms = u32(ffi+8); ls = u32(ffi+12)
                            return f"{ms>>16}.{ms&0xffff}.{ls>>16}.{ls&0xffff}"
        except: pass
        return "unknown"

    version = extract_version()
    print(f"  {CYAN('Version')} : {BOLD(version)}\n")

    # ── Imports ───────────────────────────────────────────────────────────
    IMPORTS   = {}
    IMP_BY_VA = {}
    imp_rva   = u32(opt_off+120)

    def parse_imports():
        off = rva2off(imp_rva)
        if not off: return
        while True:
            ilt = u32(off); nrva = u32(off+12); iat_rva = u32(off+16); off += 20
            if ilt == nrva == iat_rva == 0: break
            do = rva2off(nrva)
            if do is None: continue
            dll = DATA[do:DATA.index(b"\x00",do)].decode(errors="replace")
            to = rva2off(iat_rva)
            if to is None: continue
            idx = 0
            while True:
                thunk = struct.unpack_from("<Q", DATA, to+idx*8)[0]
                if thunk == 0: break
                va = image_base + iat_rva + idx*8
                if thunk & (1<<63):
                    name = f"{dll}!ord#{thunk & 0xffff}"
                else:
                    h = rva2off(thunk & 0x7FFFFFFF)
                    name = DATA[h+2:DATA.index(b"\x00",h+2)].decode(errors="replace") if h else f"unk"
                IMPORTS[name] = va; IMP_BY_VA[va] = name
                idx += 1
    parse_imports()
    iat = IMPORTS.get

    # ── Strings ───────────────────────────────────────────────────────────
    STR_ALL = []
    for m in re.finditer(rb"[\x20-\x7e]{6,}", DATA):
        STR_ALL.append((m.start(), m.group().decode()))
    for m in re.finditer(b"(?:[\x20-\x7e]\x00){6,}", DATA):
        STR_ALL.append((m.start(), m.group().decode("utf-16-le")))
    def find_str(pat):
        p = re.compile(pat, re.I)
        return [(o,s) for o,s in STR_ALL if p.search(s)]

    # ── Disassembly generation (auto, cached) ─────────────────────────────
    def need_regen():
        if FORCE_DISASM: return True
        if not os.path.exists(DISASM_FILE): return True
        if os.path.getsize(DISASM_FILE) < 1024: return True
        if os.path.getmtime(SYS_FILE) > os.path.getmtime(DISASM_FILE):
            print(f"  {YELLOW('!')} Driver newer than cache — regenerating"); return True
        return False

    def gen_disasm():
        if not need_regen():
            lc = sum(1 for _ in open(DISASM_FILE))
            print(f"  {GREEN('✓')} Cached: {DISASM_FILE} ({lc:,} lines)  {DIM('(--force to regen)')}")
            return
        tool = "objdump" if shutil.which("objdump") else ("r2" if shutil.which("r2") else None)
        if not tool:
            print(RED("[!] No disassembler. Install: apt install binutils")); sys.exit(1)
        cmd = ["objdump","-d","-M","intel",SYS_FILE] if tool=="objdump" else ["r2","-q","-c","aaa;pdf @@fcn.*",SYS_FILE]
        print(f"  {CYAN('→')} Disassembling with {BOLD(tool)} ...")
        done = threading.Event()
        def _mon():
            t = time.time()
            while not done.is_set():
                time.sleep(2)
                if os.path.exists(DISASM_FILE):
                    try: lc=sum(1 for _ in open(DISASM_FILE)); print(f"\r    {lc:,} lines ({time.time()-t:.0f}s)...",end="",flush=True)
                    except: pass
            print()
        threading.Thread(target=_mon, daemon=True).start()
        t1 = time.time()
        try:
            with open(DISASM_FILE,"w") as f, open(os.devnull,"w") as dn:
                subprocess.run(cmd, stdout=f, stderr=dn)
        except Exception as e:
            done.set(); print(RED(f"\n[!] Failed: {e}")); sys.exit(1)
        finally:
            done.set()
        if os.path.getsize(DISASM_FILE) < 1024:
            print(RED(f"[!] Empty output. Try: {' '.join(cmd)} > {DISASM_FILE}")); sys.exit(1)
        lc = sum(1 for _ in open(DISASM_FILE))
        print(f"  {GREEN('✓')} Done: {lc:,} lines in {time.time()-t1:.1f}s")

    print("[*] Checking disassembly ...")
    gen_disasm()

    # ── Disassembly index + function map ──────────────────────────────────
    print("[*] Indexing disassembly ...")
    DISASM = open(DISASM_FILE).readlines()
    ADDR2LINE = {}
    for i,line in enumerate(DISASM):
        p = line.split(":")
        if len(p) >= 2:
            try: ADDR2LINE[int(p[0].strip(),16)] = i
            except: pass

    print("[*] Detecting function boundaries ...")
    FUNC_STARTS  = []
    FUNC_BY_LINE = {}
    in_i3 = False
    for i,line in enumerate(DISASM):
        s = line.strip()
        is_i3 = s.endswith("int3") or s.endswith("\tcc")
        if in_i3 and not is_i3 and s and not s.startswith("Disassembly") and not s.startswith(stem):
            p = s.split(":")
            try: FUNC_STARTS.append((int(p[0].strip(),16), i))
            except: pass
        in_i3 = is_i3
    fid = 0
    for i in range(len(DISASM)):
        if fid+1 < len(FUNC_STARTS) and i >= FUNC_STARTS[fid+1][1]: fid += 1
        if fid < len(FUNC_STARTS): FUNC_BY_LINE[i] = FUNC_STARTS[fid][0]
    print(f"    {len(ADDR2LINE):,} addresses  |  {len(FUNC_STARTS):,} functions")

    def get_func_lines(va):
        sl = ADDR2LINE.get(va)
        if sl is None: return []
        idx = next((i for i,(v,_) in enumerate(FUNC_STARTS) if v==va), None)
        if idx is None: return []
        el = FUNC_STARTS[idx+1][1] if idx+1 < len(FUNC_STARTS) else len(DISASM)
        return DISASM[sl:el]

    def func_of(va):
        return FUNC_BY_LINE.get(ADDR2LINE.get(va))

    def find_calls(target_va):
        th = f"0x{target_va:x}"
        out = []
        for i,line in enumerate(DISASM):
            if th in line and "call" in line:
                try: out.append((int(line.split(":")[0].strip(),16), i, line.strip()))
                except: pass
        return out

    # ── Mitigations ───────────────────────────────────────────────────────
    has_cookie  = "__security_check_cookie" in IMPORTS
    has_seh     = "__C_specific_handler" in IMPORTS or "_except_handler4" in IMPORTS
    cspec_va    = iat("__C_specific_handler")
    try_count   = len(find_calls(cspec_va)) if cspec_va else 0
    MITIGATIONS = {
        "ASLR (DYNAMIC_BASE)":          ASLR,
        "DEP (NX_COMPAT)":              NX,
        "CFG (Control Flow Guard)":     CFG,
        "Force Integrity":              FINT,
        "Stack Cookies (/GS)":          has_cookie,
        "Structured Exception Handling":has_seh,
        f"__try/__except (~{try_count} blocks)": try_count > 0,
        "SEHOP (loader-enforced)":      None,
    }

    # ── IOCTL extraction ──────────────────────────────────────────────────
    METHODS = {0:"BUFFERED",1:"IN_DIRECT",2:"OUT_DIRECT",3:"NEITHER"}
    ACCESS  = {0:"ANY",1:"SPECIAL",2:"READ",3:"READ|WRITE"}
    DEVICE_TYPES = {
        0x22:"VIDEO_UNK",0x23:"VIDEO",0x2b:"MODEM",0x8000:"WMI/INTERNAL",
        0x01:"BEEP",0x07:"DISK",0x09:"FILE_SYSTEM",0x14:"NET_FS",0x39:"KSEC",
    }
    def decode_ioctl(code):
        m=code&3; fn=(code>>2)&0xfff; ac=(code>>14)&3; dt=(code>>16)&0xffff
        return dict(code=code,devtype=dt,function=fn,method=m,access=ac,
                    method_name=METHODS[m],access_name=ACCESS[ac])

    CMP_RE = re.compile(r"(?:cmp|sub)\s+(?:e[a-z]{2}|r\d+d),\s*0x([0-9a-f]{5,8})\b",re.I)
    MOV_RE = re.compile(r"mov\s+(?:e[a-z]{2}|r\d+d),\s*0x([0-9a-f]{5,8})\b",re.I)
    IOCTL_CODES = defaultdict(lambda: {"decode":None,"hits":[],"has_cmp":False,"has_mov":False})
    for i,line in enumerate(DISASM):
        for pat,kind in ((CMP_RE,"cmp"),(MOV_RE,"mov")):
            m = pat.search(line)
            if not m: continue
            val = int(m.group(1),16)
            dt=(val>>16)&0xffff; fn=(val>>2)&0xfff
            if dt in (0x22,0x23,0x2b,0x8000) and 0 < fn < 0x1000:
                try: addr=int(line.split(":")[0].strip(),16)
                except: continue
                e = IOCTL_CODES[val]
                e["decode"] = decode_ioctl(val)
                e["hits"].append((addr,i,line.strip()))
                if kind=="cmp": e["has_cmp"]=True
                else:            e["has_mov"]=True

    METHOD_NEITHER = [(c,v) for c,v in IOCTL_CODES.items() if (c&3)==3]
    METHOD_DIRECT  = [(c,v) for c,v in IOCTL_CODES.items() if (c&3) in (1,2)]

    # ── Security-relevant imports ─────────────────────────────────────────
    probe_r = iat("ProbeForRead")
    probe_w = iat("ProbeForWrite")
    pr_hex  = f"0x{probe_r:x}" if probe_r else None
    pw_hex  = f"0x{probe_w:x}" if probe_w else None

    def probe_in_func(va):
        txt = "".join(get_func_lines(va))
        return (pr_hex and pr_hex in txt), (pw_hex and pw_hex in txt)

    def reqmode_in_func(va):
        return any("+0x40]" in l and ("cmp" in l or "test" in l or "movzx" in l)
                   for l in get_func_lines(va))

    # ── Taint tracker (per-function, lightweight) ─────────────────────────
    R64 = {"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx","esi":"rsi","edi":"rdi",
           "r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11","r12d":"r12",
           "r13d":"r13","r14d":"r14","r15d":"r15","ebp":"rbp","esp":"rsp"}
    def taint(va):
        lines = get_func_lines(va)
        if not lines: return set(), []
        regs = {"rdx","rcx"}; log = []
        MV = re.compile(r"mov\s+(r\w+|e\w+),\s*(r\w+|e\w+)",re.I)
        LD = re.compile(r"mov\s+(r\w+|e\w+),\s*(?:QWORD|DWORD) PTR \[(r\w+)",re.I)
        ZX = re.compile(r"movzx\s+(r\w+|e\w+),\s*\w+ PTR \[(r\w+)",re.I)
        LA = re.compile(r"lea\s+(r\w+),\s*\[(r\w+)",re.I)
        for ln,raw in enumerate(lines):
            for pat in (MV,LD,ZX,LA):
                m = pat.search(raw)
                if m:
                    d,s = R64.get(m.group(1).lower(),m.group(1).lower()), R64.get(m.group(2).lower(),m.group(2).lower())
                    if s in regs and d not in regs:
                        regs.add(d)
                        off_m = re.search(r"\+(0x[0-9a-f]+)\]",raw,re.I)
                        log.append((ln,f"{d} ← [{s}+{off_m.group(1) if off_m else '?'}]"))
                    break
        return regs, log

    # ── Double-fetch detector ─────────────────────────────────────────────
    def double_fetch(va):
        lines = get_func_lines(va)
        if not lines: return []
        FR = re.compile(r"mov\s+\w+,\s*(?:QWORD|DWORD|WORD|BYTE) PTR \[(r\w+)\+(0x[0-9a-f]+)\]",re.I)
        reads = defaultdict(list)
        for i,line in enumerate(lines):
            m = FR.search(line)
            if m: reads[(m.group(1).lower(),m.group(2).lower())].append(i)
        out = []
        for (reg,off),rs in reads.items():
            if len(rs) < 2: continue
            between = "".join(lines[rs[0]+1:rs[1]])
            if "call" in between or re.search(r"\bj[a-z]+\b",between):
                out.append({"field":f"[{reg}+{off}]","reads":rs,
                            "first":lines[rs[0]].strip(),"second":lines[rs[1]].strip(),
                            "call_between":"call" in between})
        return out

    # ── Null-deref after alloc ────────────────────────────────────────────
    def null_deref_after_alloc(va, win=15):
        sites = find_calls(va)
        out = []
        for caller,ln,_ in sites:
            after = "".join(DISASM[ln+1:ln+win])
            if re.search(r"\[rax[\+\-]",after,re.I) and not re.search(r"test\s+rax,rax|cmp\s+rax,0",after,re.I):
                out.append({"caller":caller,"ctx":[l.rstrip() for l in DISASM[ln+1:ln+8]]})
        return out

    # ── Use-after-free detector ───────────────────────────────────────────
    def use_after_free(free_va, win=20):
        sites = find_calls(free_va)
        out = []
        for caller,ln,_ in sites:
            before = "".join(DISASM[max(0,ln-5):ln+1])
            m = re.search(r"mov\s+rcx,\s*(r\w+)",before,re.I)
            freed = m.group(1).lower() if m else None
            if not freed: continue
            after = DISASM[ln+1:ln+win]
            uses = [(j,l.strip()) for j,l in enumerate(after)
                    if re.search(rf"\[{freed}[\+\-\]]",l,re.I)]
            if uses: out.append({"caller":caller,"freed":freed,"uses":uses[:3]})
        return out

    # ── Int overflow before alloc ─────────────────────────────────────────
    def int_overflow_before_alloc(va, lookback=25):
        sites = find_calls(va)
        out = []
        for caller,ln,_ in sites:
            ctx = "".join(DISASM[max(0,ln-lookback):ln])
            risks = []
            if re.search(r"\bimul\b.*e[a-z]{2}",ctx,re.I): risks.append("IMUL-32 overflow")
            if re.search(r"\bshl\b\s+e[a-z]{2},",ctx,re.I): risks.append("SHL-32 overflow")
            if re.search(r"\badd\b\s+e[a-z]{2},\s*e[a-z]{2}",ctx,re.I): risks.append("ADD-32 no carry")
            if not risks: continue
            const = bool(re.search(r"mov\s+[re]cx,\s*0x[0-9a-f]+","".join(DISASM[max(0,ln-5):ln]),re.I))
            if const: risks = [r+" [const-size FP?]" for r in risks]
            out.append({"caller":caller,"risks":risks,"ctx":[l.rstrip() for l in DISASM[max(0,ln-10):ln]]})
        return out

    # ── ObRef type confusion ──────────────────────────────────────────────
    def ob_type_confusion(va):
        sites = find_calls(va)
        out = []
        for caller,ln,_ in sites:
            ctx = "".join(DISASM[max(0,ln-15):ln+1])
            null = bool(re.search(r"xor\s+r8d,\s*r8d|mov\s+r8,\s*0\b",ctx,re.I))
            out.append({"caller":caller,"null_type":null})
        return out

    # ── Findings collector ────────────────────────────────────────────────
    FINDINGS = []
    def add(title, sev, score, detail, addrs=None, ctx=None, fp=False):
        FINDINGS.append(dict(title=title, severity=sev, score=min(10.0,max(0.0,score)),
                             detail=detail, addresses=addrs or [], context=ctx or [],
                             false_positive_risk=fp))

    print("[*] Running checks ...")

    # 1. Mitigations
    miss = [k for k,v in MITIGATIONS.items() if v is False]
    if miss: add("Missing Binary Mitigations","INFO",2.0,f"Missing: {', '.join(miss)}")

    # 2. ProbeForRead absent globally
    if not probe_r:
        add("ProbeForRead NOT IMPORTED — Driver-Wide Gap","HIGH",8.5,
            "ProbeForRead is absent from the IAT. Every METHOD_NEITHER handler that "
            "dereferences Type3InputBuffer does so without pointer/alignment validation, "
            "creating TOCTOU and arbitrary-read primitives for any unprivileged caller.")

    # 3. METHOD_NEITHER per-handler
    seen_fva = set()
    for code,info in METHOD_NEITHER:
        for addr,_,_ in info["hits"][:2]:
            fva = func_of(addr)
            if not fva or fva in seen_fva: continue
            seen_fva.add(fva)
            has_pr,has_pw = probe_in_func(fva)
            has_rm = reqmode_in_func(fva)
            mods = ([1.5] if not has_pr else []) + ([0.5] if not has_pw else []) + ([2.0] if not has_rm else [])
            if mods:
                add(f"METHOD_NEITHER IOCTL 0x{code:08x} — Missing Probes",
                    "HIGH" if not has_rm else "MEDIUM", round(5.5+sum(mods),1),
                    f"IOCTL 0x{code:08x} routes to function 0x{fva:016x}. "
                    f"ProbeForRead: {'✓' if has_pr else '✗'}  "
                    f"ProbeForWrite: {'✓' if has_pw else '✗'}  "
                    f"RequestorMode check: {'✓' if has_rm else '✗'}",
                    [fva,addr])

    # 4. Double-fetch
    ioctl_fvas = set()
    for code,info in IOCTL_CODES.items():
        for addr,_,_ in info["hits"][:1]:
            fva = func_of(addr)
            if fva: ioctl_fvas.add(fva)
    for fva in list(ioctl_fvas)[:80]:
        for df in double_fetch(fva):
            add(f"Double-Fetch (TOCTOU) in 0x{fva:016x}","HIGH",7.0,
                f"Field {df['field']} read at two points with {'call' if df['call_between'] else 'branch'} between: "
                f"1st: {df['first']}  2nd: {df['second']}",
                [fva], fp=True)

    # 5. Null-deref after alloc
    for aname in ("ExAllocatePoolWithTag","ExAllocatePool2","ExAllocatePool3"):
        ava = iat(aname)
        if not ava: continue
        for r in null_deref_after_alloc(ava):
            add(f"Null Deref After {aname}","MEDIUM",5.0,
                f"Alloc at 0x{r['caller']:016x} derefs rax without null check.",
                [r["caller"]], ctx=r["ctx"], fp=True)

    # 6. Int overflow before alloc
    for aname in ("ExAllocatePoolWithTag","ExAllocatePool2"):
        ava = iat(aname)
        if not ava: continue
        for r in int_overflow_before_alloc(ava):
            fp = any("FP?" in x for x in r["risks"])
            add(f"Integer Overflow Before {aname}",
                "LOW" if fp else "MEDIUM", 3.5 if fp else 6.5,
                f"At 0x{r['caller']:016x}: {'; '.join(r['risks'])}",
                [r["caller"]], ctx=r["ctx"][-6:], fp=fp)

    # 7. ObRef NULL type confusion
    for oname in ("ObReferenceObjectByHandle","ObReferenceObjectByHandleWithTag"):
        ova = iat(oname)
        if not ova: continue
        nulls = [r for r in ob_type_confusion(ova) if r["null_type"]]
        if nulls:
            add(f"{oname} — NULL ObjectType (Type Confusion)","HIGH",8.5,
                f"{len(nulls)} call site(s) pass NULL ObjectType, disabling kernel type "
                f"validation. Caller-supplied handle of any object type is accepted — "
                f"classic EoP type confusion primitive.",
                [r["caller"] for r in nulls])

    # 8. Use-after-free
    for fname in ("ExFreePool","ExFreePoolWithTag","ExFreePool2"):
        fva2 = iat(fname)
        if not fva2: continue
        for r in use_after_free(fva2):
            add(f"Use-After-Free Near {fname}","HIGH",7.0,
                f"After {fname} at 0x{r['caller']:016x}, freed register {r['freed']} "
                f"is accessed {len(r['uses'])} time(s) — pool spray primitive.",
                [r["caller"]], ctx=[u[1] for u in r["uses"]], fp=True)

    # 9. ZwQuerySystemInformation
    zqsi = iat("ZwQuerySystemInformation")
    if zqsi:
        sites = find_calls(zqsi)
        add("ZwQuerySystemInformation — Potential ASLR Defeat","INFO",
            min(10.0, 3.0 + 0.4*len(sites)),
            f"{len(sites)} call site(s). If SystemModuleInformation output reaches "
            f"a user-accessible IOCTL buffer, KASLR is defeated.",
            [s[0] for s in sites[:8]], fp=True)

    # 10. Large stack frames with user data
    STKRE = re.compile(r"sub\s+rsp,\s*0x([0-9a-f]+)\b",re.I)
    for i,line in enumerate(DISASM):
        m = STKRE.search(line)
        if not m: continue
        sz = int(m.group(1),16)
        if sz < 0x500: continue
        try: addr = int(line.split(":")[0].strip(),16)
        except: continue
        fva = func_of(addr)
        if not fva: continue
        _,log = taint(fva)
        if log:
            add(f"Large Stack Frame (0x{sz:x}) With User Input","LOW",3.5,
                f"Function 0x{fva:016x} allocates 0x{sz:x} stack bytes and processes "
                f"user-controlled data — stack-buffer-overflow candidate if copy length unchecked.",
                [fva], fp=True)

    FINDINGS.sort(key=lambda f: -f["score"])

    # ── Terminal output ───────────────────────────────────────────────────
    SEV_COLOR = {"HIGH":RED,"MEDIUM":YELLOW,"LOW":CYAN,"INFO":DIM}

    print(BOLD("\n" + "═"*70))
    print(BOLD("  BINARY MITIGATIONS"))
    print(BOLD("═"*70))
    for k,v in MITIGATIONS.items():
        sym,fn = ("?",DIM) if v is None else (("✓",GREEN) if v else ("✗",RED))
        print(f"  {fn(sym)}  {k}")

    print(BOLD("\n" + "═"*70))
    print(BOLD("  IOCTL SURFACE"))
    print(BOLD("═"*70))
    print(f"  Total     : {BOLD(str(len(IOCTL_CODES)))}   "
          f"METHOD_NEITHER: {RED(str(len(METHOD_NEITHER)))}   "
          f"METHOD_DIRECT: {YELLOW(str(len(METHOD_DIRECT)))}")
    print()
    for code in sorted(IOCTL_CODES.keys()):
        info = IOCTL_CODES[code]; d = info["decode"]
        dt   = DEVICE_TYPES.get(d["devtype"],f"0x{d['devtype']:04x}")
        col  = RED if d["method"]==3 else (YELLOW if d["method"] in (1,2) else GREEN)
        tag  = " (jmptable)" if info["has_mov"] and not info["has_cmp"] else ""
        print(f"  {col(f'0x{code:08x}')}  {dt:<18s}  "
              f"Fn=0x{d['function']:03x}  {col(d['method_name']):<12s}  "
              f"{d['access_name']:<10s}  refs={len(info['hits'])}{tag}")

    print(BOLD("\n" + "═"*70))
    print(BOLD("  SECURITY FINDINGS"))
    print(BOLD("═"*70))
    print(f"  {len(FINDINGS)} total\n")
    for n,f in enumerate(FINDINGS):
        col = SEV_COLOR.get(f["severity"],DIM)
        fp  = DIM("  [confirm dynamically]") if f["false_positive_risk"] else ""
        print(f"  [{n+1}] {col(BOLD(f['severity']))} {f['score']:4.1f}  {BOLD(f['title'])}{fp}")
        print(f"       {f['detail']}")
        if f["addresses"]:
            print(f"       {' '.join(hex(a) for a in f['addresses'][:4])}")
        if f["context"]:
            for c in f["context"][:3]: print(f"         {DIM(c)}")
        print()

    SECURITY_IMPORTS = [
        ("ProbeForRead","CRITICAL if absent for METHOD_NEITHER"),
        ("ProbeForWrite","Should pair with ProbeForRead"),
        ("MmProbeAndLockPages","MDL-based probe"),
        ("MmMapIoSpace","Physical mem — high risk"),
        ("ExAllocatePoolWithTag","Check size arithmetic"),
        ("ExAllocatePool2","Modern allocator"),
        ("ExFreePoolWithTag","Track for UAF"),
        ("ExFreePool","Track for UAF"),
        ("ObReferenceObjectByHandle","Check ObjectType != NULL"),
        ("ObReferenceObjectByHandleWithTag","Check ObjectType != NULL"),
        ("ZwQuerySystemInformation","Info leak"),
        ("ZwCreateSection","Kernel section"),
        ("__security_check_cookie","Stack cookies"),
        ("__C_specific_handler","__try/__except"),
        ("RtlCopyMemory","Bulk copy — check bounds"),
    ]
    print(BOLD("═"*70))
    print(BOLD("  IMPORT AUDIT"))
    print(BOLD("═"*70))
    for name,note in SECURITY_IMPORTS:
        va = iat(name)
        if va:
            sites = find_calls(va)
            print(f"  {GREEN('✓')}  {name:<42s}  {len(sites):3d} calls  {DIM(note)}")
        else:
            crit = name in ("ProbeForRead","MmMapIoSpace")
            print(f"  {(RED if crit else DIM)('✗')}  {name:<42s}  {'NOT IMPORTED':<10s}  {DIM(note)}")

    # ── JSON ──────────────────────────────────────────────────────────────
    report = {
        "target":SYS_FILE, "version":version, "image_base":hex(image_base),
        "generated": datetime.now().isoformat(),
        "mitigations":{k:v for k,v in MITIGATIONS.items()},
        "ioctl_codes":[
            {"code":hex(c),"devtype":hex(v["decode"]["devtype"]),
             "method":v["decode"]["method_name"],"access":v["decode"]["access_name"],
             "refs":len(v["hits"]),"addrs":[hex(h[0]) for h in v["hits"][:5]]}
            for c,v in sorted(IOCTL_CODES.items())
        ],
        "findings":[
            {"id":n+1,"title":f["title"],"severity":f["severity"],
             "score":f["score"],"detail":f["detail"],
             "addresses":[hex(a) for a in f["addresses"]],
             "needs_confirmation":f["false_positive_risk"]}
            for n,f in enumerate(FINDINGS)
        ],
        "functions":len(FUNC_STARTS),
        "elapsed":round(time.time()-t0,1),
    }
    with open(json_out,"w") as jf: json.dump(report,jf,indent=2)

    # ── HTML report ───────────────────────────────────────────────────────
    if not SKIP_HTML:
        html_out = f"{stem}_report.html"
        sc = {"HIGH":"#e74c3c","MEDIUM":"#e67e22","LOW":"#3498db","INFO":"#95a5a6"}
        def mit_row(k,v):
            s,col = ("?","#888") if v is None else (("✓","#27ae60") if v else ("✗","#e74c3c"))
            return f"<tr><td>{k}</td><td style='color:{col}'>{s}</td></tr>"
        mit_rows = "".join(mit_row(k,v) for k,v in MITIGATIONS.items())
        ioctl_rows = ""
        for code,info in sorted(IOCTL_CODES.items()):
            mc = "#e74c3c" if info["decode"]["method"]==3 else ("#e67e22" if info["decode"]["method"] in (1,2) else "#27ae60")
            dt = DEVICE_TYPES.get(info["decode"]["devtype"],hex(info["decode"]["devtype"]))
            ioctl_rows += (f"<tr><td><code>0x{code:08x}</code></td><td>{dt}</td>"
                           f"<td><b style='color:{mc}'>{info['decode']['method_name']}</b></td>"
                           f"<td>{info['decode']['access_name']}</td><td>{len(info['hits'])}</td></tr>")
        finding_rows = ""
        for n,f in enumerate(FINDINGS):
            bg  = sc.get(f["severity"],"#888")
            det = f["detail"][:220]+("…" if len(f["detail"])>220 else "")
            adr = "<br>".join(hex(a) for a in f["addresses"][:3])
            sta = "⚠ Confirm" if f["false_positive_risk"] else "✓ Static"
            finding_rows += (f"<tr><td>{n+1}</td>"
                             f"<td><span class='b' style='background:{bg}'>{f['severity']}</span></td>"
                             f"<td>{f['score']:.1f}</td><td>{f['title']}</td>"
                             f"<td style='font-size:.85em;color:#555'>{det}</td>"
                             f"<td><code style='font-size:.8em'>{adr}</code></td>"
                             f"<td>{sta}</td></tr>")
        high_n = sum(1 for f in FINDINGS if f["severity"]=="HIGH")
        med_n  = sum(1 for f in FINDINGS if f["severity"]=="MEDIUM")
        html = (f"<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                f"<title>{stem} Analysis</title><style>"
                f"body{{font-family:system-ui,sans-serif;margin:0;padding:2em;background:#f4f4f4}}"
                f"h1{{color:#c0392b}}h2{{color:#2c3e50;border-bottom:2px solid #ddd;padding-bottom:6px}}"
                f".b{{color:#fff;padding:2px 8px;border-radius:3px;font-size:.8em;font-weight:bold}}"
                f"table{{border-collapse:collapse;width:100%;background:#fff;border-radius:6px;overflow:hidden;box-shadow:0 1px 4px #0001;margin-bottom:2em}}"
                f"th{{background:#2c3e50;color:#fff;padding:8px 12px;text-align:left}}"
                f"td{{padding:7px 12px;border-bottom:1px solid #eee;vertical-align:top}}"
                f"tr:hover td{{background:#f0f4ff}}.cards{{display:flex;gap:1em;flex-wrap:wrap;margin-bottom:1.5em}}"
                f".card{{background:#fff;border-radius:6px;padding:1em 2em;box-shadow:0 1px 4px #0001;text-align:center}}"
                f".num{{font-size:2.4em;font-weight:bold}}.lbl{{color:#888;font-size:.85em}}"
                f"input{{padding:5px 10px;border:1px solid #ccc;border-radius:4px;width:260px;margin-bottom:.8em}}"
                f"</style><script>function flt(){{var q=document.getElementById('q').value.toLowerCase();"
                f"document.querySelectorAll('#ft tbody tr').forEach(r=>r.style.display=r.textContent.toLowerCase().includes(q)?'':\"none\");}}"
                f"</script></head><body>"
                f"<h1>🔍 {stem}.sys — Vulnerability Report</h1>"
                f"<p><b>Version:</b> {version} &nbsp;|&nbsp; <b>Base:</b> <code>{hex(image_base)}</code>"
                f" &nbsp;|&nbsp; <b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}"
                f" &nbsp;|&nbsp; <b>Tool:</b> kernel_driver_analyze.py v4.0</p>"
                f"<div class='cards'>"
                f"<div class='card'><div class='num' style='color:#e74c3c'>{high_n}</div><div class='lbl'>HIGH</div></div>"
                f"<div class='card'><div class='num' style='color:#e67e22'>{med_n}</div><div class='lbl'>MEDIUM</div></div>"
                f"<div class='card'><div class='num'>{len(FINDINGS)}</div><div class='lbl'>Total Findings</div></div>"
                f"<div class='card'><div class='num'>{len(IOCTL_CODES)}</div><div class='lbl'>IOCTLs</div></div>"
                f"<div class='card'><div class='num'>{len(FUNC_STARTS):,}</div><div class='lbl'>Functions</div></div>"
                f"</div>"
                f"<h2>Binary Mitigations</h2><table><thead><tr><th>Mitigation</th><th>Status</th></tr></thead>"
                f"<tbody>{mit_rows}</tbody></table>"
                f"<h2>IOCTL Surface ({len(IOCTL_CODES)} codes)</h2>"
                f"<table><thead><tr><th>Code</th><th>Device Type</th><th>Method</th><th>Access</th><th>Refs</th></tr></thead>"
                f"<tbody>{ioctl_rows}</tbody></table>"
                f"<h2>Findings ({len(FINDINGS)})</h2>"
                f"<input id='q' placeholder='Filter…' onkeyup='flt()'>"
                f"<table id='ft'><thead><tr><th>#</th><th>Severity</th><th>Score</th><th>Title</th>"
                f"<th>Detail</th><th>Addresses</th><th>Status</th></tr></thead>"
                f"<tbody>{finding_rows}</tbody></table></body></html>")
        with open(html_out,"w") as hf: hf.write(html)
        print(f"  {GREEN('✓')} HTML   → {html_out}")

    # ── WinDbg script ─────────────────────────────────────────────────────
    if not SKIP_WINDBG:
        wdbg = f"{stem}_windbg.wds"
        lines_w = [f"; WinDbg script — {stem}.sys v{version}",
                   f"; Usage: $$><{wdbg}", ""]
        bp = 0; seen = set()
        for f in FINDINGS:
            if f["severity"] not in ("HIGH","MEDIUM"): continue
            for a in f["addresses"][:2]:
                if a in seen: continue
                seen.add(a); t = f["title"][:55].replace('"',"'")
                lines_w.append(f'; [{f["severity"]}] {t}')
                lines_w.append(f'bp 0x{a:016x} ".echo [HIT] 0x{a:016x} {t}; r; k 8; gc"')
                bp += 1
        lines_w += ["", f".echo [*] {bp} breakpoints set.", ".echo [*] g to continue"]
        with open(wdbg,"w") as wf: wf.write("\n".join(lines_w))
        print(f"  {GREEN('✓')} WinDbg → {wdbg} ({bp} bps)")

    # ── Ghidra script ─────────────────────────────────────────────────────
    if not SKIP_GHIDRA:
        gh = f"{stem}_ghidra.py"
        cats = {"HIGH":"VULN_HIGH","MEDIUM":"VULN_MEDIUM","LOW":"VULN_LOW","INFO":"INFO"}
        gl = ["# Ghidra bookmark+label script",
              f"# {stem}.sys v{version}",
              "from ghidra.program.model.symbol import SourceType",
              "bm=currentProgram.getBookmarkManager()",
              "sl=currentProgram.getSymbolTable()",
              "ib=currentProgram.getImageBase().getOffset()",
              f"fb=0x{image_base:016x}",
              "def va(a): return toAddr(ib+(a-fb))", ""]
        for n,f in enumerate(FINDINGS):
            if not f["addresses"]: continue
            a = f["addresses"][0]; cat = cats.get(f["severity"],"INFO")
            t = f["title"][:70].replace('"',"'")
            gl += [f"try: bm.setBookmark(va(0x{a:016x}),'{cat}','VulnScan','{t}')",
                   f"except: pass"]
        gl.append('print("Bookmarks imported")')
        with open(gh,"w") as gf: gf.write("\n".join(gl))
        print(f"  {GREEN('✓')} Ghidra → {gh} ({len(FINDINGS)} marks)")

    # ── PoC skeleton ──────────────────────────────────────────────────────
    if not SKIP_POC:
        poc = f"{stem}_poc.c"
        devs = find_str(r"\\DosDevices\\|\\GLOBAL\?\?\\")
        dev_name = devs[0][1].split("\\")[-1] if devs else stem
        stubs = []; calls = []
        for f in FINDINGS[:10]:
            if f["severity"] not in ("HIGH","MEDIUM"): continue
            cm = re.search(r"0x([0-9a-fA-F]{8})",f["title"])
            ioctl = int(cm.group(1),16) if cm else 0
            fn = re.sub(r"[^a-zA-Z0-9]","_",f["title"][:35]).lower()
            calls.append(f"    poc_{fn}(hDevice); /* {f['severity']} score={f['score']} */")
            if "NEITHER" in f["title"] or "TOCTOU" in f["title"].upper():
                body = (f"    /* TOCTOU race on METHOD_NEITHER Type3InputBuffer */\n"
                        f"    BYTE buf[0x100]; DWORD ret; memset(buf,0x41,sizeof(buf));\n"
                        f"    /* TODO: race thread: VirtualFree/VirtualAlloc on buf in parallel */\n"
                        f"    DeviceIoControl(hDevice,0x{ioctl:08X},buf,sizeof(buf),buf,sizeof(buf),&ret,NULL);\n"
                        f"    printf(\"[{fn}] ret=%lu\\n\",ret);")
            elif "ObRef" in f["title"] or "NULL ObjectType" in f["title"] or "Type Confusion" in f["title"]:
                body = (f"    /* Type confusion: wrong object type → ObRef(NULL) accepts any handle */\n"
                        f"    HANDLE hFake=CreateEvent(NULL,TRUE,FALSE,NULL);\n"
                        f"    BYTE in[0x80]={{0}},out[0x80]={{0}}; DWORD ret;\n"
                        f"    *(HANDLE*)(in+0x00)=hFake; /* adjust offset from Ghidra */\n"
                        f"    DeviceIoControl(hDevice,0x{ioctl:08X},in,sizeof(in),out,sizeof(out),&ret,NULL);\n"
                        f"    CloseHandle(hFake); printf(\"[{fn}] ret=%lu\\n\",ret);")
            elif "Use-After-Free" in f["title"] or "UAF" in f["title"]:
                body = (f"    /* UAF: spray pool→free→reclaim slot→trigger post-free write */\n"
                        f"    /* Step 1: groom pool with target-sized objects */\n"
                        f"    /* Step 2: trigger free path via specific IOCTL sequence */\n"
                        f"    /* Step 3: reclaim freed slot with HANDLE array or pipe buffer */\n"
                        f"    BYTE in[0x80]={{0}}; DWORD ret;\n"
                        f"    DeviceIoControl(hDevice,0x{ioctl:08X},in,sizeof(in),NULL,0,&ret,NULL);\n"
                        f"    printf(\"[{fn}] ret=%lu\\n\",ret);")
            elif "Integer" in f["title"] or "Overflow" in f["title"]:
                body = (f"    /* Int overflow: count*0x1c wraps at 0x924924a → alloc=0x18 bytes */\n"
                        f"    BYTE in[0x100]={{0}}; DWORD ret;\n"
                        f"    *(DWORD*)(in+0x00)=0x0924924a; /* adjust field offset from Ghidra */\n"
                        f"    DeviceIoControl(hDevice,0x{ioctl:08X},in,sizeof(in),NULL,0,&ret,NULL);\n"
                        f"    printf(\"[{fn}] ret=%lu\\n\",ret);")
            else:
                addrs_c = ", ".join(hex(a) for a in f["addresses"][:2])
                body = (f"    /* TODO: craft based on handler @ {addrs_c} */\n"
                        f"    BYTE in[0x100]={{0}},out[0x200]={{0}}; DWORD ret;\n"
                        f"    DeviceIoControl(hDevice,0x{ioctl:08X},in,sizeof(in),out,sizeof(out),&ret,NULL);\n"
                        f"    printf(\"[{fn}] ret=%lu\\n\",ret);")
            stubs.append(f"void poc_{fn}(HANDLE hDevice) {{\n{body}\n}}")

        stub_text = "\n\n".join(stubs)
        call_text = "\n".join(calls)
        poc_c = (f"/*\n * {stem}_poc.c  — Auto-generated PoC skeleton\n"
                 f" * Driver   : {stem}.sys  v{version}\n"
                 f" * Device   : {dev_name}\n"
                 f" * Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"
                 f" * Build    : x86_64-w64-mingw32-gcc {stem}_poc.c -o {stem}_poc.exe -lntdll\n"
                 f" *            cl {stem}_poc.c /Fe:{stem}_poc.exe\n"
                 f" * Run in a VM with WinDbg kernel-attached: $$><{stem}_windbg.wds\n"
                 f" */\n"
                 f"#include <windows.h>\n#include <stdio.h>\n#include <stdint.h>\n\n"
                 f"typedef LONG NTSTATUS;\n"
                 f"NTSTATUS NTAPI NtCreateSection(PHANDLE,ACCESS_MASK,PVOID,PLARGE_INTEGER,ULONG,ULONG,HANDLE);\n"
                 f"NTSTATUS NTAPI NtMapViewOfSection(HANDLE,HANDLE,PVOID*,ULONG_PTR,SIZE_T,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG);\n"
                 f"NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE,PVOID);\n\n"
                 f"#define DEVICE_PATH L\"\\\\\\\\.\\\\{dev_name}\"\n\n"
                 f"{stub_text}\n\n"
                 f"int main(void) {{\n"
                 f"    printf(\"[*] {stem}.sys PoC v{version}\\n\");\n"
                 f"    HANDLE h=CreateFileW(DEVICE_PATH,GENERIC_READ|GENERIC_WRITE,\n"
                 f"        FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);\n"
                 f"    if(h==INVALID_HANDLE_VALUE){{fprintf(stderr,\"[-] Open failed: %lu\\n\",GetLastError());return 1;}}\n"
                 f"    printf(\"[+] Device opened\\n\");\n"
                 f"{call_text}\n"
                 f"    CloseHandle(h); printf(\"[+] Done\\n\"); return 0;\n}}\n")
        with open(poc,"w") as pf: pf.write(poc_c)
        print(f"  {GREEN('✓')} PoC    → {poc} ({len(stubs)} stubs)")

    # ── Summary ───────────────────────────────────────────────────────────
    el = time.time()-t0
    high_n = sum(1 for f in FINDINGS if f["severity"]=="HIGH")
    med_n  = sum(1 for f in FINDINGS if f["severity"]=="MEDIUM")
    print(BOLD(f"\n{'═'*70}"))
    print(BOLD(f"  {stem}.sys v{version}  |  {el:.1f}s"))
    print(f"  {RED(str(high_n))} HIGH  {YELLOW(str(med_n))} MEDIUM  {len(FINDINGS)} total  |  {len(FUNC_STARTS):,} functions")
    print(f"  JSON   → {json_out}")
    if not SKIP_HTML:   print(f"  HTML   → {stem}_report.html")
    if not SKIP_WINDBG: print(f"  WinDbg → {stem}_windbg.wds")
    if not SKIP_GHIDRA: print(f"  Ghidra → {stem}_ghidra.py")
    if not SKIP_POC:    print(f"  PoC    → {stem}_poc.c")
    print(BOLD(f"{'═'*70}\n"))
    return report

# ══════════════════════════════════════════════════════════════════════════
# PATCH DIFF MODE
# ══════════════════════════════════════════════════════════════════════════
def run_diff(old_sys, new_sys):
    print(BOLD(f"\n{'='*70}"))
    print(BOLD( "  PATCH DIFF MODE"))
    print(BOLD(f"  Old: {old_sys}  New: {new_sys}"))
    print(BOLD(f"{'='*70}\n"))

    def func_hashes(path):
        hashes = {}
        try:
            out = subprocess.check_output(["objdump","-d","-M","intel",path],
                                          stderr=subprocess.DEVNULL).decode(errors="replace")
            cur = None; cur_b = []
            for line in out.splitlines():
                fm = re.match(r"^([0-9a-f]+) <",line)
                if fm:
                    if cur and cur_b: hashes[int(cur,16)] = hashlib.md5(bytes(cur_b)).hexdigest()[:8]
                    cur=fm.group(1); cur_b=[]
                else:
                    bm = re.match(r"^\s+[0-9a-f]+:\s+((?:[0-9a-f]{2} )+)",line)
                    if bm: cur_b.extend(int(x,16) for x in bm.group(1).split())
        except: pass
        return hashes

    print("[*] Hashing old ..."); old = func_hashes(old_sys); print(f"    {len(old):,} functions")
    print("[*] Hashing new ..."); new = func_hashes(new_sys);  print(f"    {len(new):,} functions\n")

    added   = {v for v in new if v not in old}
    removed = {v for v in old if v not in new}
    changed = {v for v in new if v in old and new[v]!=old[v]}

    print(f"  {GREEN('+')} Added   : {len(added)}")
    print(f"  {RED('-')} Removed : {len(removed)}")
    print(f"  {YELLOW('~')} Changed : {BOLD(str(len(changed)))}  {DIM('← focus here for n-day')}\n")

    if changed:
        print(BOLD("  Changed addresses (prioritize in analyzer):"))
        for v in sorted(changed)[:50]: print(f"    {YELLOW('~')} 0x{v:016x}")
        if len(changed)>50: print(f"    {DIM(f'+ {len(changed)-50} more...')}")

    stem   = Path(new_sys).stem
    out_f  = f"{stem}_diff.json"
    with open(out_f,"w") as df:
        json.dump({"old":old_sys,"new":new_sys,
                   "added":[hex(v) for v in sorted(added)],
                   "removed":[hex(v) for v in sorted(removed)],
                   "changed":[hex(v) for v in sorted(changed)]},df,indent=2)
    print(f"\n  {GREEN('✓')} Diff → {out_f}")
    print(f"  {CYAN('→')} Run: python3 {sys.argv[0]} {new_sys}")

# ══════════════════════════════════════════════════════════════════════════
# BATCH MODE
# ══════════════════════════════════════════════════════════════════════════
def run_batch(directory):
    drivers = sorted(glob.glob(os.path.join(directory,"*.sys")))
    if not drivers: print(RED(f"[!] No .sys files in {directory}")); return
    print(BOLD(f"\n{'='*70}"))
    print(BOLD(f"  BATCH MODE — {len(drivers)} drivers"))
    print(BOLD(f"{'='*70}"))
    rows = []
    for drv in drivers:
        print(f"\n{CYAN('►')} {os.path.basename(drv)}")
        try:
            r = run_single(drv)
            if r is None: rows.append({"driver":os.path.basename(drv),"error":"parse failed"}); continue
            rows.append({"driver":os.path.basename(drv),"version":r.get("version","?"),
                         "HIGH":sum(1 for f in r["findings"] if f["severity"]=="HIGH"),
                         "MEDIUM":sum(1 for f in r["findings"] if f["severity"]=="MEDIUM"),
                         "total":len(r["findings"]),"ioctl":len(r["ioctl_codes"])})
        except Exception as e:
            rows.append({"driver":os.path.basename(drv),"error":str(e)})
    csv_f = os.path.join(directory,"batch_summary.csv")
    with open(csv_f,"w",newline="") as cf:
        if rows: w=csv.DictWriter(cf,fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
    print(BOLD(f"\n{'='*70}  BATCH SUMMARY"))
    print(f"  {'Driver':<35} {'Version':<18} {'HIGH':>4} {'MED':>4} {'TOT':>5}")
    print(f"  {'─'*65}")
    for r in rows:
        if "error" in r: print(f"  {r['driver']:<35} ERROR: {r.get('error','')[:30]}")
        else:
            hc = RED(str(r.get("HIGH",0))) if r.get("HIGH",0) else "0"
            print(f"  {r['driver'][:35]:<35} {r.get('version','?')[:18]:<18} {hc:>4} {r.get('MEDIUM',0):>4} {r.get('total',0):>5}")
    print(f"\n  CSV → {csv_f}")

# ══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════
if BATCH_DIR:
    run_batch(BATCH_DIR)
elif DIFF_OLD:
    if not SYS_FILE: print(RED("[!] --diff requires a target .sys file too")); sys.exit(1)
    run_diff(DIFF_OLD, SYS_FILE)
else:
    run_single(SYS_FILE)
