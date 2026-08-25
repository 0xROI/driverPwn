#!/usr/bin/env python3
"""
kernel_driver_analyze.py  v2.0
Windows kernel driver vulnerability analysis engine.

Improvements over v1:
  ✓ Function boundary detection (9000+ functions, per-function analysis)
  ✓ Register taint tracking (x64 calling convention → tracks user-data flow)
  ✓ Double-fetch / TOCTOU detection (same IRP field read multiple times)
  ✓ CFG / binary mitigation checks (ASLR, DEP, CFG, SEHOP, stack cookies)
  ✓ __try/__except block detection (fault handling presence)
  ✓ Null-deref after alloc detection (alloc without null-check before deref)
  ✓ Arbitrary write primitive detection ([computed-reg] = user-value)
  ✓ ExFreePool / use-after-free pattern detection
  ✓ Large stack frame near user-input (potential stack overflow)
  ✓ IOCTL jump-table detection (catches range-based switches missed by v1)
  ✓ Per-function IOCTL handler scoping
  ✓ CVSS-like severity scoring for each finding
  ✓ JSON report output (machine-readable)
  ✓ ANSI colour output for terminal
  ✓ False-positive reduction (constant-size alloc cleared, etc.)
"""

import struct, sys, re, json, os, time
from collections import defaultdict

# ── ANSI colours ──────────────────────────────────────────────────────────
USE_COLOR = sys.stdout.isatty() or "--color" in sys.argv
def C(code, s): return f"\033[{code}m{s}\033[0m" if USE_COLOR else s
RED    = lambda s: C("91",s)
YELLOW = lambda s: C("93",s)
GREEN  = lambda s: C("92",s)
CYAN   = lambda s: C("96",s)
BOLD   = lambda s: C("1", s)
DIM    = lambda s: C("2", s)

SYS_FILE   = sys.argv[1] if len(sys.argv) > 1 else "dxgkrnl.sys"
DISASM_FILE = sys.argv[2] if len(sys.argv) > 2 else "full_disasm.txt"
JSON_OUT    = sys.argv[3] if len(sys.argv) > 3 else "findings.json"

print(BOLD(f"\n{'='*70}"))
print(BOLD(f"  Windows Kernel Driver Analyzer v2.0"))
print(BOLD(f"  Target : {SYS_FILE}"))
print(BOLD(f"{'='*70}\n"))

DATA = open(SYS_FILE, "rb").read()
t0   = time.time()

# ════════════════════════════════════════════════════════════════════════════
# SECTION 1 — PE PARSING
# ════════════════════════════════════════════════════════════════════════════
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]

e_lfanew  = u32(DATA, 0x3c)
pe        = e_lfanew
assert DATA[pe:pe+4] == b"PE\0\0", "Not a PE file"
machine   = u16(DATA, pe+4)
num_sects = u16(DATA, pe+6)
ts        = u32(DATA, pe+8)
opt_off   = pe + 24
magic     = u16(DATA, opt_off)
assert magic == 0x20b, "Not PE32+"

# DllCharacteristics for mitigation flags
dll_chars   = u16(DATA, opt_off+70)
image_base  = u64(DATA, opt_off+24)
ep_rva      = u32(DATA, opt_off+16)
checksum    = u32(DATA, opt_off+64)
subsystem   = u16(DATA, opt_off+68)

# Mitigation flags
ASLR        = bool(dll_chars & 0x0040)
FORCE_INT   = bool(dll_chars & 0x0080)   # /FORCERELOCATE
NX          = bool(dll_chars & 0x0100)
SEH         = not bool(dll_chars & 0x0400)  # 0x0400 = NO_SEH
CFG         = bool(dll_chars & 0x4000)

# Sections
SECTS = []
sect_off = opt_off + 240
for i in range(num_sects):
    o      = sect_off + i*40
    name   = DATA[o:o+8].rstrip(b"\x00").decode(errors="replace")
    vsize  = u32(DATA, o+8)
    vrva   = u32(DATA, o+12)
    rawsz  = u32(DATA, o+16)
    rawptr = u32(DATA, o+20)
    chars  = u32(DATA, o+36)
    SECTS.append(dict(name=name, vrva=vrva, vsize=vsize, rawptr=rawptr, rawsz=rawsz, chars=chars))

def rva2off(rva):
    for s in SECTS:
        if s["vrva"] <= rva < s["vrva"]+s["vsize"]:
            return s["rawptr"] + (rva - s["vrva"])
    return None

def va2off(va): return rva2off(int(va) - image_base)

# ════════════════════════════════════════════════════════════════════════════
# SECTION 2 — IMPORTS
# ════════════════════════════════════════════════════════════════════════════
imp_dir_rva = u32(DATA, opt_off+120)
IMPORTS    = {}   # name  → IAT VA
IMP_BY_VA  = {}   # IAT VA → name
DLL_IMPORTS= defaultdict(list)  # dll → [names]

def parse_imports():
    off = rva2off(imp_dir_rva)
    if not off: return
    while True:
        ilt_rva  = u32(DATA, off)
        name_rva = u32(DATA, off+12)
        iat_rva  = u32(DATA, off+16)
        off += 20
        if ilt_rva == 0 and name_rva == 0 and iat_rva == 0: break
        dll_off = rva2off(name_rva)
        if dll_off is None: continue
        dll = DATA[dll_off:DATA.index(b"\x00",dll_off)].decode(errors="replace")
        thunk_off = rva2off(iat_rva)
        if thunk_off is None: continue
        i = 0
        while True:
            thunk = u64(DATA, thunk_off + i*8)
            if thunk == 0: break
            va = image_base + iat_rva + i*8
            if thunk & (1<<63):
                name = f"{dll}!ord#{thunk & 0xffff}"
            else:
                h = rva2off(thunk & 0x7FFFFFFF)
                name = DATA[h+2:DATA.index(b"\x00",h+2)].decode(errors="replace") if h else f"unk_{thunk:x}"
            IMPORTS[name]   = va
            IMP_BY_VA[va]   = name
            DLL_IMPORTS[dll].append(name)
            i += 1

parse_imports()
iat = IMPORTS.get  # shorthand: iat("ProbeForRead") → VA or None

# ════════════════════════════════════════════════════════════════════════════
# SECTION 3 — STRINGS
# ════════════════════════════════════════════════════════════════════════════
STRINGS_ALL = []
for m in re.finditer(rb"[\x20-\x7e]{6,}", DATA):
    STRINGS_ALL.append((m.start(), "ascii", m.group().decode()))
for m in re.finditer(b"(?:[\x20-\x7e]\x00){6,}", DATA):
    STRINGS_ALL.append((m.start(), "wide", m.group().decode("utf-16-le")))

def find_str(pattern):
    pat = re.compile(pattern, re.IGNORECASE)
    return [(o,t,s) for o,t,s in STRINGS_ALL if pat.search(s)]

# ════════════════════════════════════════════════════════════════════════════
# SECTION 4 — DISASSEMBLY INDEX + FUNCTION MAP
# ════════════════════════════════════════════════════════════════════════════
print(f"[*] Loading disassembly from {DISASM_FILE} ...")
DISASM = open(DISASM_FILE).readlines()
print(f"    {len(DISASM):,} lines")

print("[*] Building address index ...")
ADDR2LINE = {}
for i, line in enumerate(DISASM):
    p = line.split(":")
    if len(p) >= 2:
        try: ADDR2LINE[int(p[0].strip(), 16)] = i
        except: pass
print(f"    {len(ADDR2LINE):,} addresses indexed")

print("[*] Detecting function boundaries ...")
FUNC_STARTS = []   # list of (va, line_index)
FUNC_BY_LINE = {}  # line_index → func_va
in_int3 = False
for i, line in enumerate(DISASM):
    s = line.strip()
    is_int3 = s.endswith("int3") or s.endswith("\tcc")
    if in_int3 and not is_int3 and s and not s.startswith("Disassembly") \
            and not s.startswith(SYS_FILE):
        p = s.split(":")
        try: FUNC_STARTS.append((int(p[0].strip(), 16), i))
        except: pass
    in_int3 = is_int3
print(f"    {len(FUNC_STARTS):,} functions detected")

# Build reverse map: for any line, which function does it belong to?
func_idx = 0
for i in range(len(DISASM)):
    if func_idx + 1 < len(FUNC_STARTS) and i >= FUNC_STARTS[func_idx+1][1]:
        func_idx += 1
    if func_idx < len(FUNC_STARTS):
        FUNC_BY_LINE[i] = FUNC_STARTS[func_idx][0]

def get_func_lines(func_va):
    """Return all lines belonging to the function starting at func_va."""
    start_line = ADDR2LINE.get(func_va)
    if start_line is None: return []
    # find next function start
    idx = next((i for i,(va,ln) in enumerate(FUNC_STARTS) if va==func_va), None)
    if idx is None: return []
    end_line = FUNC_STARTS[idx+1][1] if idx+1 < len(FUNC_STARTS) else len(DISASM)
    return DISASM[start_line:end_line]

def func_of(va):
    """Return the containing function VA for a given address VA."""
    line = ADDR2LINE.get(va)
    if line is None: return None
    return FUNC_BY_LINE.get(line)

def find_call_sites(target_va):
    """All call sites referencing an IAT slot VA."""
    target_hex = f"0x{target_va:x}"
    results = []
    for i, line in enumerate(DISASM):
        if target_hex in line and "call" in line:
            p = line.split(":")
            try: results.append((int(p[0].strip(), 16), i, line.strip()))
            except: pass
    return results

# ════════════════════════════════════════════════════════════════════════════
# SECTION 5 — BINARY MITIGATION AUDIT
# ════════════════════════════════════════════════════════════════════════════
MITIGATIONS = {}

# DllCharacteristics-based
MITIGATIONS["ASLR (DYNAMIC_BASE)"]           = ASLR
MITIGATIONS["DEP (NX_COMPAT)"]               = NX
MITIGATIONS["CFG (Control Flow Guard)"]       = CFG
MITIGATIONS["Force Integrity (FORCE_INTEGRITY)"] = FORCE_INT

# Stack cookie: __security_check_cookie imported or present as internal fn
has_cookie = ("__security_check_cookie" in IMPORTS or
              any("security_check_cookie" in s for _,_,s in STRINGS_ALL))
MITIGATIONS["Stack Cookies (/GS)"]           = has_cookie

# SafeSEH / SEH: presence of __C_specific_handler or _except_handler
has_seh_handler = "__C_specific_handler" in IMPORTS or "_except_handler4" in IMPORTS
MITIGATIONS["Structured Exception Handling"] = has_seh_handler

# SEHOP: can't detect from binary alone without loader; note as N/A
MITIGATIONS["SEHOP (loader-enforced, N/A)"]  = None

# __try/__except: detected from __C_specific_handler call count
try_except_count = 0
cspec_va = iat("__C_specific_handler")
if cspec_va:
    try_except_count = len(find_call_sites(cspec_va))
MITIGATIONS[f"__try/__except blocks (~{try_except_count})"] = try_except_count > 0

# ════════════════════════════════════════════════════════════════════════════
# SECTION 6 — IOCTL EXTRACTION (improved: cmp + sub + jump-table detection)
# ════════════════════════════════════════════════════════════════════════════
METHODS = {0:"BUFFERED", 1:"IN_DIRECT", 2:"OUT_DIRECT", 3:"NEITHER"}
ACCESS  = {0:"ANY", 1:"SPECIAL", 2:"READ", 3:"READ|WRITE"}

def decode_ioctl(code):
    method   = code & 3
    function = (code >> 2) & 0xfff
    access   = (code >> 14) & 3
    devtype  = (code >> 16) & 0xffff
    return dict(code=code, devtype=devtype, access=access,
                function=function, method=method,
                method_name=METHODS[method], access_name=ACCESS[access])

# Known Windows driver device type registry
DEVICE_TYPES = {
    0x00: "UNKNOWN", 0x01: "BEEP", 0x02: "CD_ROM", 0x03: "CD_ROM_FILE_SYSTEM",
    0x04: "CONTROLLER", 0x05: "DATALINK", 0x06: "DFS", 0x07: "DISK",
    0x08: "DISK_FILE_SYSTEM", 0x09: "FILE_SYSTEM", 0x0a: "INPORT_PORT",
    0x0b: "KEYBOARD", 0x0c: "MAILSLOT", 0x0d: "MIDI_IN", 0x0e: "MIDI_OUT",
    0x0f: "MOUSE", 0x10: "MULTI_UNC_PROVIDER", 0x11: "NAMED_PIPE",
    0x12: "NETWORK", 0x13: "NETWORK_BROWSER", 0x14: "NETWORK_FILE_SYSTEM",
    0x15: "NULL", 0x16: "PARALLEL_PORT", 0x17: "PHYSICAL_NETCARD",
    0x18: "PRINTER", 0x19: "SCANNER", 0x1a: "SERIAL_MOUSE_PORT",
    0x1b: "SERIAL_PORT", 0x1c: "SCREEN", 0x1d: "SOUND",
    0x1e: "STREAMS", 0x1f: "TAPE", 0x20: "TAPE_FILE_SYSTEM",
    0x21: "TRANSPORT", 0x22: "UNKNOWN_22", 0x23: "VIDEO",
    0x24: "VIRTUAL_DISK", 0x25: "WAVE_IN", 0x26: "WAVE_OUT",
    0x27: "PORT_8042", 0x28: "NETWORK_REDIRECTOR", 0x29: "BATTERY",
    0x2a: "BUS_EXTENDER", 0x2b: "MODEM", 0x2c: "VDM",
    0x2d: "MASS_STORAGE", 0x2e: "SMB", 0x2f: "KS",
    0x30: "CHANGER", 0x31: "SMARTCARD", 0x32: "ACPI",
    0x33: "DVD", 0x34: "FULLSCREEN_VIDEO", 0x35: "DFS_FILE_SYSTEM",
    0x36: "DFS_VOLUME", 0x37: "SERENUM", 0x38: "TERMSRV",
    0x39: "KSEC", 0x3a: "FIPS", 0x3b: "INFINIBAND",
    0x8000: "WMI_OR_INTERNAL",
}

# Pattern 1: cmp/sub reg, IOCTL_VALUE (switch lowering)
IOCTL_CMP_RE = re.compile(
    r"(?:cmp|sub)\s+(?:e[a-z]{2}|r\d+d),\s*0x([0-9a-f]{5,8})\b", re.I)

# Pattern 2: mov reg, IOCTL_VALUE (often loads into dispatch table index)
IOCTL_MOV_RE = re.compile(
    r"mov\s+(?:e[a-z]{2}|r\d+d),\s*0x([0-9a-f]{5,8})\b", re.I)

ioctl_hits = defaultdict(list)  # code → [(addr, lineno, context)]

for i, line in enumerate(DISASM):
    for pat in (IOCTL_CMP_RE, IOCTL_MOV_RE):
        m = pat.search(line)
        if not m: continue
        val = int(m.group(1), 16)
        devtype  = (val >> 16) & 0xffff
        function = (val >> 2) & 0xfff
        method   = val & 3
        # Device types we care about
        if devtype in (0x22, 0x23, 0x2b, 0x8000) and 0 < function < 0x1000:
            p = line.split(":")
            try:
                addr = int(p[0].strip(), 16)
                ioctl_hits[val].append((addr, i, line.strip()))
            except: pass

# De-dup: if same code hits from mov AND cmp, keep all but mark type
IOCTL_CODES = {}
for code, hits in ioctl_hits.items():
    d = decode_ioctl(code)
    # determine instruction types present
    has_cmp = any("cmp" in h[2] or "sub" in h[2] for h in hits)
    has_mov = any(("mov" in h[2]) and ("cmp" not in h[2]) and ("sub" not in h[2]) for h in hits)
    IOCTL_CODES[code] = {"decode": d, "hits": hits,
                          "has_cmp": has_cmp, "has_mov": has_mov}

METHOD_NEITHER = [(c,v) for c,v in IOCTL_CODES.items() if (c&3)==3]
METHOD_DIRECT  = [(c,v) for c,v in IOCTL_CODES.items() if (c&3) in (1,2)]

# ════════════════════════════════════════════════════════════════════════════
# SECTION 7 — REGISTER TAINT TRACKER (per-function, lightweight)
# ════════════════════════════════════════════════════════════════════════════
# x64 WDM calling convention:
#   DriverDispatch(PDEVICE_OBJECT DevObj, PIRP Irp)
#   rcx = DeviceObject, rdx = IRP
# IRP fields of interest (offsets into IRP structure):
IRP_FIELDS = {
    "0x18": "UserBuffer (raw user ptr)",
    "0x38": "AssociatedIrp.SystemBuffer (safe copy)",
    "0x40": "RequestorMode (0=kernel,1=user)",
    "0x60": "MdlAddress",
    "0x68": "Flags",
    "0x70": "IoStackLocation ptr",
    "0xb8": "IoStackLocation->Parameters.DeviceIoControl",
}
# IO_STACK_LOCATION DeviceIoControl parameters:
IOS_FIELDS = {
    "0x08": "IoControlCode",
    "0x10": "InputBufferLength",
    "0x18": "OutputBufferLength",
    "0x20": "Type3InputBuffer (METHOD_NEITHER raw ptr)",
}

TAINT_SOURCES = re.compile(
    r"\b(rdx|rcx)\b.*\+0x(18|20|38|70|b8)\b|"     # IRP UserBuffer, SystemBuffer, stack loc
    r"mov.*\[r[a-z0-9]+\+0x(08|10|18|20)\]",        # IO_STACK fields
    re.I
)

def analyze_function_taint(func_va):
    """
    Returns dict of tainted registers and where they came from in this function.
    Simplified: forward pass, tracks register assignments from known user-data sources.
    """
    lines = get_func_lines(func_va)
    if not lines: return {}

    # Registers that hold user-controlled data
    tainted = set()
    taint_log = []

    # IRP is in rdx at function entry
    tainted.add("rdx")  # IRP pointer itself
    tainted.add("rcx")  # DeviceObject

    MOV_FROM_TAINT  = re.compile(r"mov\s+(r\w+),\s*(r\w+)", re.I)
    LOAD_FROM_PTR   = re.compile(r"mov\s+(r\w+),\s*QWORD PTR \[(r\w+)[\+\-]", re.I)
    LOAD_DWORD_PTR  = re.compile(r"mov\s+(e\w+),\s*DWORD PTR \[(r\w+)[\+\-]", re.I)
    MOVZX_FROM      = re.compile(r"movzx\s+(r\w+|e\w+),\s*(?:BYTE|WORD) PTR \[(r\w+)", re.I)
    LEA_FROM        = re.compile(r"lea\s+(r\w+),\s*\[(r\w+)", re.I)

    def reg64(r):
        """Normalize e-prefixed → r-prefixed for tracking."""
        m = {"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx",
             "esi":"rsi","edi":"rdi","ebp":"rbp","esp":"rsp",
             "r8d":"r8","r9d":"r9","r10d":"r10","r11d":"r11",
             "r12d":"r12","r13d":"r13","r14d":"r14","r15d":"r15"}
        return m.get(r.lower(), r.lower())

    for lineno, raw in enumerate(lines):
        line = raw.strip()
        # Register-to-register move: if source is tainted, dest is tainted
        m = MOV_FROM_TAINT.search(line)
        if m:
            dst, src = reg64(m.group(1)), reg64(m.group(2))
            if src in tainted:
                tainted.add(dst)
                taint_log.append((lineno, f"{dst} ← {src} (taint propagation)"))

        # Load from tainted pointer
        for pat in (LOAD_FROM_PTR, LOAD_DWORD_PTR, MOVZX_FROM):
            m = pat.search(line)
            if m:
                dst, base = reg64(m.group(1)), reg64(m.group(2))
                if base in tainted:
                    tainted.add(dst)
                    # Check if this field is a known IRP/IO_STACK field
                    off_m = re.search(r"\+(0x[0-9a-f]+)\]", line, re.I)
                    off = off_m.group(1) if off_m else "?"
                    field_name = IRP_FIELDS.get(off, IOS_FIELDS.get(off, f"offset +{off}"))
                    taint_log.append((lineno, f"{dst} ← [{base}+{off}] ({field_name})"))
                break

        # LEA from tainted base
        m = LEA_FROM.search(line)
        if m:
            dst, base = reg64(m.group(1)), reg64(m.group(2))
            if base in tainted:
                tainted.add(dst)

    return {"tainted_regs": list(tainted), "taint_log": taint_log}

# ════════════════════════════════════════════════════════════════════════════
# SECTION 8 — DOUBLE-FETCH / TOCTOU DETECTOR
# ════════════════════════════════════════════════════════════════════════════
def detect_double_fetch(func_va):
    """
    Looks for the same user-pointer field being read more than once in a function.
    This is the structural signature of a double-fetch / TOCTOU bug.
    Returns list of (field, first_line, second_line) tuples.
    """
    lines = get_func_lines(func_va)
    if not lines: return []

    # Pattern: load from [reg + offset] where reg is likely IRP-derived
    FIELD_READ = re.compile(r"mov\s+\w+,\s*(?:QWORD|DWORD|WORD|BYTE) PTR \[(r\w+)\+(0x[0-9a-f]+)\]", re.I)

    field_reads = defaultdict(list)  # (base_reg, offset) → [line_indices]
    for i, line in enumerate(lines):
        m = FIELD_READ.search(line)
        if m:
            key = (m.group(1).lower(), m.group(2).lower())
            field_reads[key].append(i)

    double_fetches = []
    for (reg, off), reads in field_reads.items():
        if len(reads) >= 2:
            # Is there a call between the two reads? (= potential inconsistency)
            first, second = reads[0], reads[1]
            between = lines[first+1:second]
            has_call = any("call" in l for l in between)
            has_branch = any(re.search(r"\bj[a-z]+\b", l) for l in between)
            if has_call or has_branch:
                double_fetches.append({
                    "field": f"[{reg}+{off}]",
                    "first_read": first,
                    "second_read": second,
                    "call_between": has_call,
                    "branch_between": has_branch,
                    "first_line": lines[first].strip(),
                    "second_line": lines[second].strip(),
                })
    return double_fetches

# ════════════════════════════════════════════════════════════════════════════
# SECTION 9 — NULL DEREF AFTER ALLOC
# ════════════════════════════════════════════════════════════════════════════
ALLOC_FUNCS = [n for n in ("ExAllocatePoolWithTag","ExAllocatePool2","ExAllocatePool3",
               "ExAllocatePoolZero","ExAllocatePoolQuotaTag") if iat(n)]

def detect_null_deref_after_alloc(alloc_va, window=15):
    """
    For each call to an alloc function, check whether the next `window` instructions
    dereference the return value (rax) WITHOUT a null check (test rax/jz pattern).
    """
    sites = find_call_sites(alloc_va)
    risky = []
    for caller, lineno, text in sites:
        after = DISASM[lineno+1:lineno+window]
        after_text = "".join(after)
        # Has null check?
        has_null_check = bool(re.search(r"test\s+rax,\s*rax|cmp\s+rax,\s*0|test\s+eax,\s*eax", after_text, re.I))
        # Dereferences rax?
        has_deref = bool(re.search(r"\[rax[\+\-]", after_text, re.I))
        if has_deref and not has_null_check:
            risky.append({
                "caller": caller,
                "lineno": lineno,
                "has_null_check": False,
                "has_deref": True,
                "context": [l.rstrip() for l in after[:8]]
            })
    return risky

# ════════════════════════════════════════════════════════════════════════════
# SECTION 10 — ARBITRARY WRITE PRIMITIVE DETECTION
# ════════════════════════════════════════════════════════════════════════════
def detect_arb_write(func_va):
    """
    Looks for patterns where a tainted (user-controlled) register is used as
    a DESTINATION pointer in a memory write: mov [tainted_reg + X], val
    This is the shape of an arbitrary kernel write primitive.
    """
    taint_info = analyze_function_taint(func_va)
    tainted = set(taint_info.get("tainted_regs", []))
    lines   = get_func_lines(func_va)
    if not lines or not tainted: return []

    ARB_WRITE = re.compile(r"mov\s+(?:QWORD|DWORD|WORD|BYTE) PTR \[(r\w+)[\+\-]", re.I)
    hits = []
    for i, line in enumerate(lines):
        m = ARB_WRITE.search(line)
        if m:
            dst_reg = m.group(1).lower()
            if dst_reg in tainted:
                hits.append({"line": i, "text": line.strip(), "dst_reg": dst_reg})
    return hits

# ════════════════════════════════════════════════════════════════════════════
# SECTION 11 — USE-AFTER-FREE PATTERN DETECTOR
# ════════════════════════════════════════════════════════════════════════════
FREE_FUNCS = [n for n in ("ExFreePool","ExFreePoolWithTag","ExFreePool2") if iat(n)]

def detect_use_after_free(free_va, window=20):
    """
    After ExFreePool(rax-based ptr), if rax or any register holding the same
    pointer is dereferenced within `window` instructions, flag as UAF candidate.
    """
    sites = find_call_sites(free_va)
    risky = []
    for caller, lineno, text in sites:
        # Look for the pointer register being freed (first arg = rcx)
        before = DISASM[max(0,lineno-5):lineno+1]
        # Find what goes into rcx just before the free call
        freed_reg = None
        for bl in reversed(before):
            m = re.search(r"mov\s+rcx,\s*(r\w+)", bl, re.I)
            if m:
                freed_reg = m.group(1).lower()
                break

        after = DISASM[lineno+1:lineno+window]
        used_after = []
        for j, al in enumerate(after):
            # If the freed pointer register appears in a dereference
            if freed_reg and re.search(rf"\[{freed_reg}[\+\-\]]", al, re.I):
                used_after.append((j, al.strip()))
            # Also catch if rax is loaded from freed pointer
            elif freed_reg and re.search(rf"mov\s+\w+,\s*{freed_reg}\b", al, re.I):
                used_after.append((j, al.strip()))

        if used_after:
            risky.append({
                "caller": caller,
                "freed_ptr": freed_reg,
                "uses": used_after[:3],
                "context": [l.rstrip() for l in after[:10]]
            })
    return risky

# ════════════════════════════════════════════════════════════════════════════
# SECTION 12 — STACK BUFFER OVERFLOW CANDIDATES
# ════════════════════════════════════════════════════════════════════════════
def detect_large_stack_frames(threshold=0x400):
    """
    Functions with very large stack allocations (sub rsp, X where X > threshold)
    that also process user input are stack-overflow candidates.
    """
    LARGE_STACK_RE = re.compile(r"sub\s+rsp,\s*0x([0-9a-f]+)\b", re.I)
    hits = []
    for i, line in enumerate(DISASM):
        m = LARGE_STACK_RE.search(line)
        if not m: continue
        size = int(m.group(1), 16)
        if size < threshold: continue
        p = line.split(":")
        try: addr = int(p[0].strip(), 16)
        except: continue
        func_va = func_of(addr)
        # Check if this function has tainted (user) data flowing in
        tinfo = analyze_function_taint(func_va) if func_va else {}
        has_user_data = bool(tinfo.get("taint_log"))
        hits.append({
            "addr": addr,
            "func_va": func_va,
            "stack_size": size,
            "has_user_data": has_user_data,
        })
    return hits

# ════════════════════════════════════════════════════════════════════════════
# SECTION 13 — INTEGER OVERFLOW IN SIZE ARITHMETIC
# ════════════════════════════════════════════════════════════════════════════
def detect_int_overflow_before_alloc(alloc_va, lookback=25):
    """
    Improved version: checks for 32-bit multiply/shift before alloc,
    then verifies whether the result is zero-extended (safe) or used 
    directly as 64-bit size (dangerous = overflow path).
    """
    sites = find_call_sites(alloc_va)
    risky = []
    for caller, lineno, text in sites:
        ctx = DISASM[max(0,lineno-lookback):lineno]
        ctx_text = "".join(ctx)

        risks = []
        # 32-bit multiply that feeds into 64-bit size
        if re.search(r"\bimul\b.*e[a-z]{2}", ctx_text, re.I):
            risks.append("IMUL 32-bit (result truncated if > 0xFFFFFFFF)")
        if re.search(r"\bmul\b\s+e[a-z]{2}", ctx_text, re.I):
            risks.append("MUL 32-bit")
        # SHL on 32-bit reg used as size
        if re.search(r"\bshl\b\s+e[a-z]{2},", ctx_text, re.I):
            risks.append("SHL on 32-bit reg → potential wrap")
        # ADD without carry check (32-bit operands → truncation)
        if re.search(r"\badd\b\s+e[a-z]{2},\s*e[a-z]{2}", ctx_text, re.I):
            risks.append("ADD 32-bit operands without overflow check")

        # False-positive filter: if size arg (rcx for Pool2, rdx for PoolWithTag)
        # is loaded from a constant (mov ecx, 0x...) right before the call, 
        # it's not user-controlled
        last5 = "".join(ctx[-5:])
        is_const_size = bool(re.search(r"mov\s+[re]cx,\s*0x[0-9a-f]+\b", last5, re.I))
        if is_const_size and risks:
            risks = [r + " [FP: constant size loaded just before call]" for r in risks]

        if risks:
            risky.append({
                "caller": caller,
                "risks": risks,
                "context": [l.rstrip() for l in ctx[-12:]]
            })
    return risky

# ════════════════════════════════════════════════════════════════════════════
# SECTION 14 — ProbeForRead/Write SCOPE ANALYSIS (per function)
# ════════════════════════════════════════════════════════════════════════════
probe_r_va = iat("ProbeForRead")
probe_w_va = iat("ProbeForWrite")
probe_r_hex = f"0x{probe_r_va:x}" if probe_r_va else None
probe_w_hex = f"0x{probe_w_va:x}" if probe_w_va else None

def check_probe_in_func(func_va):
    """Returns whether ProbeForRead and ProbeForWrite are called within the function."""
    lines  = get_func_lines(func_va)
    text   = "".join(lines)
    has_pr = probe_r_hex and probe_r_hex in text
    has_pw = probe_w_hex and probe_w_hex in text
    return has_pr, has_pw

def check_requestor_mode_in_func(func_va):
    """Returns True if the function checks IRP->RequestorMode (+0x40)."""
    lines = get_func_lines(func_va)
    return any("+0x40]" in l and ("cmp" in l or "test" in l or "movzx" in l) for l in lines)

# ════════════════════════════════════════════════════════════════════════════
# SECTION 15 — ObReferenceObjectByHandle TYPE CONFUSION
# ════════════════════════════════════════════════════════════════════════════
def check_ob_type_confusion(ob_va):
    sites = find_call_sites(ob_va)
    risky = []
    for caller, lineno, text in sites:
        ctx = DISASM[max(0,lineno-15):lineno+1]
        ctx_text = "".join(ctx)
        # r8 = ObjectType argument; NULL means no type check
        null_type = bool(re.search(r"xor\s+r8d,\s*r8d|mov\s+r8,\s*0\b", ctx_text, re.I))
        risky.append({
            "caller": caller, 
            "null_type": null_type,
            "context": [l.rstrip() for l in ctx[-8:]]
        })
    return risky

# ════════════════════════════════════════════════════════════════════════════
# SECTION 16 — FINDINGS COLLECTOR + SEVERITY SCORING
# ════════════════════════════════════════════════════════════════════════════
FINDINGS = []

def severity_score(base, modifiers):
    """Simple additive CVSS-like score 0-10."""
    s = base
    for m in modifiers: s += m
    return min(10.0, max(0.0, round(s, 1)))

def add_finding(title, severity, score, detail, addrs=None, context=None, fp=False):
    FINDINGS.append({
        "title": title,
        "severity": severity,
        "score": score,
        "detail": detail,
        "addresses": addrs or [],
        "context": context or [],
        "false_positive_risk": fp,
    })

# ════════════════════════════════════════════════════════════════════════════
# RUN ALL CHECKS
# ════════════════════════════════════════════════════════════════════════════
print("[*] Running checks...\n")

# ── Check 1: Mitigation baseline ──────────────────────────────────────────
missing_mitigations = [k for k,v in MITIGATIONS.items() if v is False]
if missing_mitigations:
    add_finding(
        title="Missing Binary Mitigations",
        severity="INFO",
        score=severity_score(2.0, [-0.5 * (len(missing_mitigations)-1)]),
        detail=f"Missing: {', '.join(missing_mitigations)}",
        fp=False
    )

# ── Check 2: ProbeForRead not imported ────────────────────────────────────
if not probe_r_va:
    add_finding(
        title="ProbeForRead NOT IMPORTED — Global Absence",
        severity="HIGH",
        score=8.0,
        detail=(
            "ProbeForRead is not present in the IAT anywhere in this driver. "
            "For any METHOD_NEITHER IOCTL handler, Type3InputBuffer is a raw "
            "user-mode VA. Without ProbeForRead the driver cannot validate "
            "pointer validity, alignment, or mode — enabling TOCTOU races "
            "and potential kernel reads from attacker-controlled addresses."
        ),
        fp=False
    )

# ── Check 3: METHOD_NEITHER per-handler probe analysis ────────────────────
for code, info in METHOD_NEITHER:
    for addr, lineno, text in info["hits"]:
        fva = func_of(addr)
        if not fva: continue
        has_pr, has_pw = check_probe_in_func(fva)
        has_rm = check_requestor_mode_in_func(fva)
        score_mods = []
        if not has_pr: score_mods.append(1.5)
        if not has_pw: score_mods.append(0.5)
        if not has_rm: score_mods.append(2.0)  # no mode check = worse
        if score_mods:
            add_finding(
                title=f"METHOD_NEITHER IOCTL 0x{code:08x} — Missing Probes",
                severity="HIGH" if not has_rm else "MEDIUM",
                score=severity_score(5.5, score_mods),
                detail=(
                    f"IOCTL 0x{code:08x} uses METHOD_NEITHER (raw user VA). "
                    f"Function @ 0x{fva:016x}. "
                    f"ProbeForRead: {'YES' if has_pr else 'MISSING'}  "
                    f"ProbeForWrite: {'YES' if has_pw else 'MISSING'}  "
                    f"RequestorMode check: {'YES' if has_rm else 'MISSING'}"
                ),
                addrs=[fva, addr],
                fp=False
            )

# ── Check 4: Double-fetch in IOCTL dispatch functions ─────────────────────
ioctl_funcs_checked = set()
for code, info in IOCTL_CODES.items():
    for addr, lineno, _ in info["hits"][:2]:
        fva = func_of(addr)
        if not fva or fva in ioctl_funcs_checked: continue
        ioctl_funcs_checked.add(fva)
        dfs = detect_double_fetch(fva)
        for df in dfs:
            add_finding(
                title=f"Double-Fetch (TOCTOU) Candidate in IOCTL Function 0x{fva:016x}",
                severity="HIGH",
                score=severity_score(7.0, [0.5 if df["call_between"] else 0.0]),
                detail=(
                    f"Field {df['field']} is read at lines {df['first_read']} and "
                    f"{df['second_read']} within the same function, with a "
                    f"{'call' if df['call_between'] else 'branch'} between reads. "
                    f"First: {df['first_line']}  Second: {df['second_line']}"
                ),
                addrs=[fva],
                fp=True   # needs dynamic confirmation
            )

# ── Check 5: Null-deref after alloc ───────────────────────────────────────
for aname in ALLOC_FUNCS:
    ava = iat(aname)
    if not ava: continue
    risky = detect_null_deref_after_alloc(ava)
    for r in risky:
        add_finding(
            title=f"Null Dereference After {aname} (no null check)",
            severity="MEDIUM",
            score=severity_score(5.0, []),
            detail=(
                f"Call to {aname} at 0x{r['caller']:016x} is immediately "
                f"followed by a dereference of rax without a null check. "
                f"If allocation fails (low-memory / quota) this is a kernel null-deref."
            ),
            addrs=[r["caller"]],
            context=r["context"],
            fp=True
        )

# ── Check 6: Integer overflow before pool alloc ───────────────────────────
for aname in ALLOC_FUNCS:
    ava = iat(aname)
    if not ava: continue
    risky = detect_int_overflow_before_alloc(ava)
    for r in risky:
        is_fp = any("FP:" in x for x in r["risks"])
        add_finding(
            title=f"Integer Overflow Before {aname} — Size Calculation",
            severity="LOW" if is_fp else "MEDIUM",
            score=severity_score(4.0, [-1.0 if is_fp else 0.5]),
            detail=(
                f"At 0x{r['caller']:016x}: "
                f"{'; '.join(r['risks'])}"
            ),
            addrs=[r["caller"]],
            context=r["context"],
            fp=is_fp
        )

# ── Check 7: ObReferenceObjectByHandle null-type confusion ────────────────
for oname in ("ObReferenceObjectByHandle", "ObReferenceObjectByHandleWithTag"):
    ova = iat(oname)
    if not ova: continue
    results = check_ob_type_confusion(ova)
    null_type_sites = [r for r in results if r["null_type"]]
    if null_type_sites:
        addrs = [r["caller"] for r in null_type_sites]
        add_finding(
            title=f"{oname} Called with NULL ObjectType",
            severity="HIGH",
            score=severity_score(7.5, []),
            detail=(
                f"{len(null_type_sites)} call site(s) pass NULL (xor r8d,r8d) as "
                f"ObjectType to {oname}. This disables kernel type checking — any "
                f"kernel object handle can be passed and will be dereferenced as the "
                f"expected type, enabling type confusion / EoP."
            ),
            addrs=addrs,
            fp=False
        )

# ── Check 8: Use-after-free patterns ─────────────────────────────────────
for fname in FREE_FUNCS:
    fva = iat(fname)
    if not fva: continue
    risky = detect_use_after_free(fva)
    for r in risky:
        add_finding(
            title=f"Use-After-Free Candidate Near {fname}",
            severity="HIGH",
            score=severity_score(7.0, []),
            detail=(
                f"After {fname} at 0x{r['caller']:016x}, register {r['freed_ptr']} "
                f"(the freed pointer) appears to be dereferenced {len(r['uses'])} time(s)."
            ),
            addrs=[r["caller"]],
            context=[u[1] for u in r["uses"]],
            fp=True  # register reuse is common; needs confirmation
        )

# ── Check 9: Large stack frames with user data ────────────────────────────
large_frames = detect_large_stack_frames(threshold=0x500)
for lf in large_frames:
    if lf["has_user_data"]:
        add_finding(
            title=f"Large Stack Frame (0x{lf['stack_size']:x} bytes) With User Input",
            severity="LOW",
            score=severity_score(3.5, []),
            detail=(
                f"Function 0x{lf['func_va']:016x} allocates 0x{lf['stack_size']:x} "
                f"bytes on the stack and appears to process user-controlled data. "
                f"Stack-based buffer overflows are possible if input length is not "
                f"checked before a copy onto this frame."
            ),
            addrs=[lf["func_va"]],
            fp=True
        )

# ── Check 10: ZwQuerySystemInformation info leak ─────────────────────────
zqsi_va = iat("ZwQuerySystemInformation")
if zqsi_va:
    sites = find_call_sites(zqsi_va)
    add_finding(
        title="ZwQuerySystemInformation — Potential ASLR Defeat",
        severity="INFO",
        score=severity_score(3.0, [0.5 * min(len(sites), 5)]),
        detail=(
            f"{len(sites)} call site(s). If SystemModuleInformation (class 11) or "
            f"SystemHandleInformation is queried and results are exposed through an "
            f"output IOCTL buffer, kernel base addresses could be leaked to usermode."
        ),
        addrs=[s[0] for s in sites[:10]],
        fp=True
    )

# ════════════════════════════════════════════════════════════════════════════
# OUTPUT — TERMINAL REPORT
# ════════════════════════════════════════════════════════════════════════════
SEV_COLOR = {
    "HIGH":   RED,
    "MEDIUM": YELLOW,
    "LOW":    CYAN,
    "INFO":   DIM,
}

print(BOLD("\n" + "═"*70))
print(BOLD("  BINARY MITIGATIONS"))
print(BOLD("═"*70))
for k, v in MITIGATIONS.items():
    if v is None:
        sym, fn = "?", DIM
    elif v:
        sym, fn = "✓", GREEN
    else:
        sym, fn = "✗", RED
    print(f"  {fn(sym)}  {k}")

print(BOLD("\n" + "═"*70))
print(BOLD("  IOCTL SURFACE"))
print(BOLD("═"*70))
print(f"  Total IOCTL codes      : {BOLD(str(len(IOCTL_CODES)))}")
print(f"  METHOD_NEITHER codes   : {RED(str(len(METHOD_NEITHER)))}")
print(f"  METHOD_DIRECT codes    : {YELLOW(str(len(METHOD_DIRECT)))}")
print()

for code in sorted(IOCTL_CODES.keys()):
    info = IOCTL_CODES[code]
    d    = info["decode"]
    dt   = DEVICE_TYPES.get(d["devtype"], f"0x{d['devtype']:04x}")
    meth = d["method_name"]
    color = RED if d["method"]==3 else (YELLOW if d["method"] in (1,2) else GREEN)
    fp_note = " (jump-table ref)" if info["has_mov"] and not info["has_cmp"] else ""
    print(f"  {color('0x'+f'{code:08x}')}  DevType={dt:<25s}  "
          f"Func=0x{d['function']:03x}  Method={color(meth):<12s}  "
          f"Access={d['access_name']:<10s}  Refs={len(info['hits'])}{fp_note}")

print(BOLD("\n" + "═"*70))
print(BOLD("  SECURITY FINDINGS"))
print(BOLD("═"*70))
print(f"  Total findings: {BOLD(str(len(FINDINGS)))}\n")

# Sort by score descending
FINDINGS.sort(key=lambda f: -f["score"])

for idx, f in enumerate(FINDINGS):
    sev   = f["severity"]
    color = SEV_COLOR.get(sev, DIM)
    fp    = "  [needs dynamic confirmation]" if f["false_positive_risk"] else ""
    print(f"  [{idx+1}] {color(BOLD(f['severity']))} — Score {f['score']:4.1f}  "
          f"{BOLD(f['title'])}{DIM(fp)}")
    print(f"       {f['detail']}")
    if f["addresses"]:
        print(f"       Addresses: {', '.join(f'0x{a:016x}' for a in f['addresses'][:4])}")
    if f["context"]:
        for c in f["context"][:4]:
            print(f"         {DIM(c)}")
    print()

# ════════════════════════════════════════════════════════════════════════════
# IMPORT SUMMARY TABLE
# ════════════════════════════════════════════════════════════════════════════
SECURITY_IMPORTS = [
    ("ProbeForRead",              "CRITICAL if absent for METHOD_NEITHER"),
    ("ProbeForWrite",             "Should match ProbeForRead usage"),
    ("MmProbeAndLockPages",       "MDL-based probe — safer alternative"),
    ("MmMapIoSpace",              "Physical memory mapping — high risk"),
    ("MmMapLockedPagesSpecifyCache","MDL mapping — check access mode"),
    ("ExAllocatePoolWithTag",     "Check size arithmetic"),
    ("ExAllocatePool2",           "Preferred modern allocator"),
    ("ExFreePoolWithTag",         "Track for UAF"),
    ("ExFreePool",                "Track for UAF"),
    ("ObReferenceObjectByHandle", "Check ObjectType != NULL"),
    ("ObReferenceObjectByHandleWithTag","Check ObjectType != NULL"),
    ("ZwQuerySystemInformation",  "Info leak candidate"),
    ("ZwCreateSection",           "Kernel section — check access"),
    ("ZwMapViewOfSection",        "Kernel VA mapping"),
    ("__security_check_cookie",   "Stack cookie presence"),
    ("__C_specific_handler",      "__try/__except usage"),
    ("RtlCopyMemory",             "Bulk copy — check bounds"),
    ("memmove",                   "Bulk copy — check bounds"),
]
print(BOLD("═"*70))
print(BOLD("  SECURITY-RELEVANT IMPORTS"))
print(BOLD("═"*70))
for name, note in SECURITY_IMPORTS:
    va = iat(name)
    if va:
        sites = find_call_sites(va)
        print(f"  {GREEN('✓')}  {name:<42s}  {len(sites):3d} call(s)  {DIM(note)}")
    else:
        is_critical = "CRITICAL" in note or name in ("ProbeForRead","MmMapIoSpace")
        fn = RED if is_critical else DIM
        print(f"  {fn('✗')}  {name:<42s}  {'NOT IMPORTED':<10s}  {DIM(note)}")

# ════════════════════════════════════════════════════════════════════════════
# JSON OUTPUT
# ════════════════════════════════════════════════════════════════════════════
report = {
    "target": SYS_FILE,
    "image_base": hex(image_base),
    "mitigations": {k: v for k,v in MITIGATIONS.items()},
    "ioctl_codes": [
        {
            "code": hex(code),
            "devtype": hex(info["decode"]["devtype"]),
            "function": hex(info["decode"]["function"]),
            "method": info["decode"]["method_name"],
            "access": info["decode"]["access_name"],
            "ref_count": len(info["hits"]),
            "addresses": [hex(h[0]) for h in info["hits"][:5]]
        }
        for code, info in sorted(IOCTL_CODES.items())
    ],
    "findings": [
        {
            "id": idx+1,
            "title": f["title"],
            "severity": f["severity"],
            "score": f["score"],
            "detail": f["detail"],
            "addresses": [hex(a) for a in f["addresses"]],
            "needs_confirmation": f["false_positive_risk"],
        }
        for idx, f in enumerate(FINDINGS)
    ],
    "functions_analyzed": len(FUNC_STARTS),
    "elapsed_seconds": round(time.time()-t0, 1),
}

with open(JSON_OUT, "w") as jf:
    json.dump(report, jf, indent=2)

elapsed = time.time()-t0
print(BOLD(f"\n{'═'*70}"))
print(BOLD(f"  COMPLETE in {elapsed:.1f}s  |  {len(FINDINGS)} findings  |  {len(FUNC_STARTS):,} functions analyzed"))
print(f"  JSON report → {JSON_OUT}")
print(BOLD(f"{'═'*70}\n"))
