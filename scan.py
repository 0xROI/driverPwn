#!/usr/bin/env python3
"""
dxgkrnl_analyze.py
Replicates core logic of:
  - DrvEye  : device name, security descriptor, import enumeration
  - ioctlance: IOCTL code extraction, METHOD_NEITHER detection,
                missing ProbeForRead/Write, dangerous patterns
"""
import struct, sys, re, json, os
from collections import defaultdict

SYS = sys.argv[1] if len(sys.argv) > 1 else "dxgkrnl.sys"
DATA = open(SYS, "rb").read()

# ── PE helpers ─────────────────────────────────────────────────────────────
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def u64(b,o): return struct.unpack_from("<Q",b,o)[0]

e_lfanew = u32(DATA, 0x3c)
pe = e_lfanew
assert DATA[pe:pe+4] == b"PE\0\0"
machine   = u16(DATA, pe+4)
num_sects = u16(DATA, pe+6)
opt_off   = pe + 24
magic     = u16(DATA, opt_off)
assert magic == 0x20b, "Not PE32+"
image_base   = u64(DATA, opt_off+24)
ep_rva       = u32(DATA, opt_off+16)
num_dirs     = u32(DATA, opt_off+108)

SECTS = []
sect_off = opt_off + 240   # OptionalHeader size for PE32+
for i in range(num_sects):
    o  = sect_off + i*40
    name = DATA[o:o+8].rstrip(b"\x00").decode(errors="replace")
    vsize  = u32(DATA, o+8)
    vrva   = u32(DATA, o+12)
    rawsz  = u32(DATA, o+16)
    rawptr = u32(DATA, o+20)
    SECTS.append(dict(name=name,vrva=vrva,vsize=vsize,rawptr=rawptr,rawsz=rawsz))

def rva2off(rva):
    for s in SECTS:
        if s["vrva"] <= rva < s["vrva"]+s["vsize"]:
            return s["rawptr"] + (rva - s["vrva"])
    return None

def va2off(va): return rva2off(va - image_base)

# ── Imports ────────────────────────────────────────────────────────────────
imp_dir_rva  = u32(DATA, opt_off+120)
imp_dir_size = u32(DATA, opt_off+124)
iat_dir_rva  = u32(DATA, opt_off+192)
iat_dir_size = u32(DATA, opt_off+196)

IMPORTS = {}   # name -> VA
IMP_BY_VA = {} # VA -> name
dll_ord  = {}

def parse_imports():
    off = rva2off(imp_dir_rva)
    if off is None: return
    while True:
        ilt_rva  = u32(DATA, off)
        name_rva = u32(DATA, off+12)
        iat_rva  = u32(DATA, off+16)
        off += 20
        if ilt_rva == 0 and name_rva == 0 and iat_rva == 0: break
        dll_name_off = rva2off(name_rva)
        if dll_name_off is None: continue
        end = DATA.index(b"\x00", dll_name_off)
        dll = DATA[dll_name_off:end].decode(errors="replace")
        thunk_off = rva2off(iat_rva)
        if thunk_off is None: continue
        i = 0
        while True:
            thunk = u64(DATA, thunk_off + i*8)
            if thunk == 0: break
            va = image_base + iat_rva + i*8
            if thunk & (1<<63):   # ordinal
                name = f"{dll}!ord#{thunk & 0xffff}"
            else:
                hint_off = rva2off(thunk & 0x7FFFFFFF)
                if hint_off is not None:
                    name_e = DATA.index(b"\x00", hint_off+2)
                    name = DATA[hint_off+2:name_e].decode(errors="replace")
                else:
                    name = f"unk_{thunk:x}"
            IMPORTS[name] = va
            IMP_BY_VA[va]  = name
            i += 1

parse_imports()

def iat(name):
    """Return the IAT VA for a named import, or None."""
    return IMPORTS.get(name)

# ── Strings scan ───────────────────────────────────────────────────────────
STRINGS_WIDE = []
STRINGS_ASCII = []

def scan_strings():
    # ASCII >= 6 chars
    for m in re.finditer(rb"[\x20-\x7e]{6,}", DATA):
        STRINGS_ASCII.append((m.start(), m.group().decode()))
    # UTF-16LE >= 6 chars
    for m in re.finditer(b"(?:[\x20-\x7e]\x00){6,}", DATA):
        raw = m.group()
        text = raw.decode("utf-16-le")
        STRINGS_WIDE.append((m.start(), text))

scan_strings()

def find_strings_matching(pattern):
    pat = re.compile(pattern, re.IGNORECASE)
    results = []
    for off, s in STRINGS_ASCII + STRINGS_WIDE:
        if pat.search(s):
            results.append((off, s))
    return results

# ── Disassembly helpers (work on existing disasm file) ─────────────────────
DISASM_FILE = "full_disasm.txt"
DISASM = open(DISASM_FILE).readlines() if os.path.exists(DISASM_FILE) else []

def addr_to_lineno():
    """Build map: hex_addr_str -> line_index (0-based)"""
    m = {}
    for i, line in enumerate(DISASM):
        parts = line.split(":")
        if len(parts) >= 2:
            try:
                addr = int(parts[0].strip(), 16)
                m[addr] = i
            except: pass
    return m
print("[*] Indexing disassembly...")
ADDR2LINE = addr_to_lineno()
print(f"    {len(ADDR2LINE):,} addresses indexed")

def get_lines_around_addr(va, before=30, after=80):
    idx = ADDR2LINE.get(va)
    if idx is None: return []
    return DISASM[max(0,idx-before): idx+after]

def find_call_sites(target_va):
    """Find all disassembly lines that call the IAT slot for target_va"""
    results = []
    target_hex = f"0x{target_va:x}"
    for i, line in enumerate(DISASM):
        if target_hex in line and ("call" in line or "ff 15" in line):
            # extract caller address
            parts = line.split(":")
            try:
                caller = int(parts[0].strip(), 16)
                results.append((caller, i, line.strip()))
            except: pass
    return results

# ── 1. DrvEye: Device names & security ────────────────────────────────────
print("\n" + "="*70)
print("[DrvEye] DEVICE NAMES & SYMBOLS")
print("="*70)
dev_strings = find_strings_matching(r"\\Device\\|\\DosDevices\\|\\GLOBAL\?\?\\|\\BaseNamedObjects\\")
for off, s in dev_strings:
    print(f"  0x{off:08x}  {s}")

print("\n[DrvEye] DEVICE TYPE & CHARACTERISTICS")
# Parse PE optional header for subsystem
subsystem = u16(DATA, opt_off+68)
print(f"  Subsystem          : {subsystem} (1=Native/Driver)")
print(f"  Image Base         : 0x{image_base:016x}")
print(f"  Entry Point RVA    : 0x{ep_rva:08x}  (VA: 0x{image_base+ep_rva:016x})")
print(f"  Sections           : {', '.join(s['name'] for s in SECTS)}")

# ── 2. Import audit ────────────────────────────────────────────────────────
print("\n" + "="*70)
print("[DrvEye] SECURITY-RELEVANT IMPORTS")
print("="*70)
DANGEROUS_IMPORTS = [
    ("ProbeForRead",         "safe - but ABSENCE near user-buf access is the bug"),
    ("ProbeForWrite",        "safe - but ABSENCE near user-buf access is the bug"),
    ("MmProbeAndLockPages",  "safe - but ABSENCE is the bug"),
    ("MmMapIoSpace",         "exposes physical memory - privesc primitive"),
    ("MmMapLockedPagesSpecifyCache","kernel VA mapping"),
    ("ZwMapViewOfSection",   "section mapping"),
    ("MmAllocateContiguousMemory","physical-contiguous alloc"),
    ("MmAllocateNonCachedMemory","non-cached alloc"),
    ("RtlCopyMemory",        "bulk copy - check bounds"),
    ("memmove",              "bulk copy - check bounds"),
    ("memcpy",               "bulk copy - check bounds"),
    ("ExAllocatePoolWithTag","pool allocation - check size calc"),
    ("ExAllocatePool2",      "pool allocation - check size calc"),
    ("ExAllocatePool3",      "pool allocation - check size calc"),
    ("ObReferenceObjectByHandle","handle → object - check type"),
    ("ObReferenceObjectByHandleWithTag","handle → object - check type"),
    ("ZwQuerySystemInformation","info leak candidate"),
    ("ZwCreateSection",      "section creation - kernel VA"),
    ("HalTranslateBusAddress","physical addr translation"),
]
found_imports = {}
for imp_name, note in DANGEROUS_IMPORTS:
    va = iat(imp_name)
    if va:
        print(f"  [+] {imp_name:<45s} VA=0x{va:016x}  # {note}")
        found_imports[imp_name] = va
    else:
        print(f"  [-] {imp_name:<45s} NOT IMPORTED")

# ── 3. ioctlance: IOCTL code extraction ───────────────────────────────────
print("\n" + "="*70)
print("[ioctlance] IOCTL CODE EXTRACTION")
print("="*70)

# IOCTL encoding: bits[31:16]=DevType, bits[15:14]=Access, bits[13:2]=Function, bits[1:0]=Method
# dxgkrnl uses DeviceType 0x22 (FILE_DEVICE_VIDEO) and 0x2b (DXGI device)
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

# Extract all IOCTL-shaped immediates from disassembly
# Pattern: cmp eax/ecx/edx/r8d/r9d/r10d, 0x<val>
# IOCTL codes for dxgkrnl: DevType 0x22 → range 0x220000..0x22ffff
#                           DevType 0x2b → range 0x2b0000..0x2bffff
# Also look for sub-patterns (sub eax, IOCTL is common in switch lowering)
IOCTL_PATTERN = re.compile(
    r"(?:cmp|sub|mov|lea|add)\s+(?:e?[a-z]{2,3}|r\d+d),\s*0x([0-9a-f]{5,8})\b",
    re.IGNORECASE
)
ioctl_candidates = {}
for i, line in enumerate(DISASM):
    m = IOCTL_PATTERN.search(line)
    if not m: continue
    val = int(m.group(1), 16)
    devtype = (val >> 16) & 0xffff
    function = (val >> 2) & 0xfff
    method = val & 3
    # Filter: known dxgkrnl device types, plausible function numbers
    if devtype in (0x22, 0x23, 0x2b, 0x8000) and 0 < function < 0x800:
        addr_parts = line.split(":")
        try:
            addr = int(addr_parts[0].strip(), 16)
        except: continue
        dec = decode_ioctl(val)
        if val not in ioctl_candidates:
            ioctl_candidates[val] = {"decode": dec, "sites": []}
        ioctl_candidates[val]["sites"].append((addr, i))

print(f"  Found {len(ioctl_candidates)} unique IOCTL codes\n")
METHOD_NEITHER_CODES = []
for code in sorted(ioctl_candidates.keys()):
    info = ioctl_candidates[code]
    d = info["decode"]
    sites = info["sites"]
    flag = "  *** METHOD_NEITHER ***" if d["method"] == 3 else ""
    print(f"  0x{code:08x}  DevType=0x{d['devtype']:04x}  Func=0x{d['function']:03x}  "
          f"Method={d['method_name']:<10s}  Access={d['access_name']:<10s}  "
          f"Sites={len(sites)}{flag}")
    if d["method"] == 3:
        METHOD_NEITHER_CODES.append((code, sites))

# ── 4. ioctlance: METHOD_NEITHER handler analysis ─────────────────────────
print("\n" + "="*70)
print("[ioctlance] METHOD_NEITHER HANDLERS — PROBE ANALYSIS")
print("="*70)
print("  METHOD_NEITHER = raw user VA in Type3InputBuffer/UserBuffer")
print("  WITHOUT ProbeForRead/Write → kernel directly touches user memory\n")

probe_read_va  = found_imports.get("ProbeForRead")
probe_write_va = found_imports.get("ProbeForWrite")

def hex_va(va): return f"0x{va:016x}" if va else "0x{?}"

print(f"  ProbeForRead  IAT slot: {hex_va(probe_read_va)}")
print(f"  ProbeForWrite IAT slot: {hex_va(probe_write_va)}\n")

# For each METHOD_NEITHER call site, look at surrounding code for Probe calls
probe_r_hex = f"0x{probe_read_va:x}" if probe_read_va else None
probe_w_hex = f"0x{probe_write_va:x}" if probe_write_va else None

for code, sites in METHOD_NEITHER_CODES:
    print(f"  IOCTL 0x{code:08x} [{METHODS[code&3]}] — {len(sites)} reference site(s)")
    for addr, lineno in sites[:3]:
        ctx = DISASM[max(0,lineno-5): lineno+60]
        ctx_text = "".join(ctx)
        has_probe_r = probe_r_hex and probe_r_hex in ctx_text
        has_probe_w = probe_w_hex and probe_w_hex in ctx_text
        print(f"    Site @ 0x{addr:016x}:")
        print(f"      ProbeForRead  nearby: {'YES' if has_probe_r else 'NO  <-- MISSING?'}")
        print(f"      ProbeForWrite nearby: {'YES' if has_probe_w else 'NO  <-- MISSING?'}")
    print()

# ── 5. ioctlance: RequestorMode checks ────────────────────────────────────
print("="*70)
print("[ioctlance] RequestorMode CHECK ANALYSIS")
print("="*70)
# RequestorMode at IRP+0x40 (byte), value 0=KernelMode 1=UserMode
# Safe drivers check: cmp byte ptr [irp+0x40], 0 / jz KernelMode
req_mode_pattern = re.compile(r"\+0x40\].*,\s*0x0|\+0x40\],\s*0")
req_mode_hits = []
for i, line in enumerate(DISASM):
    if "+0x40]" in line and ("cmp" in line or "test" in line or "movzx" in line):
        addr_parts = line.split(":")
        try:
            addr = int(addr_parts[0].strip(), 16)
            req_mode_hits.append((addr, i, line.strip()))
        except: pass
print(f"  Found {len(req_mode_hits)} RequestorMode check(s) (IRP+0x40)")
for addr, lineno, text in req_mode_hits[:20]:
    print(f"    0x{addr:016x}: {text}")

# ── 6. Dangerous pattern: arbitrary size pool alloc with user input ────────
print("\n" + "="*70)
print("[ioctlance] POOL ALLOCATION SIZE — OVERFLOW CANDIDATES")
print("="*70)
pool_vas = [found_imports.get(n) for n in 
            ("ExAllocatePoolWithTag","ExAllocatePool2","ExAllocatePool3","ExAllocatePoolZero")
            if found_imports.get(n)]
print(f"  Pool alloc imports present: {len(pool_vas)}")
for va in pool_vas:
    name = IMP_BY_VA.get(va,"?")
    sites = find_call_sites(va)
    print(f"\n  [{name}] — {len(sites)} call site(s)")
    for caller, lineno, text in sites[:5]:
        # Look back 20 lines for size computation: multiply, shift, add patterns
        ctx = DISASM[max(0,lineno-20): lineno+2]
        ctx_text = "".join(ctx)
        has_mul  = "imul" in ctx_text or "mul " in ctx_text
        has_shl  = "shl " in ctx_text
        # Is there a size that comes from rcx/rdx (user-controlled)?
        has_ucopy = "movzx" in ctx_text or "movsx" in ctx_text
        risk = []
        if has_mul:  risk.append("MUL/IMUL before alloc (overflow?)")
        if has_shl:  risk.append("SHL before alloc (overflow?)")
        if has_ucopy: risk.append("zero/sign-extend before alloc (user input?)")
        if risk:
            print(f"    ** 0x{caller:016x}: {', '.join(risk)}")
            for l in ctx[-10:]: print("       " + l.rstrip())

# ── 7. Dangerous: ObReferenceObjectByHandle — type confusion ──────────────
print("\n" + "="*70)
print("[ioctlance] HANDLE→OBJECT REFERENCE — TYPE CONFUSION CANDIDATES")
print("="*70)
for fname in ("ObReferenceObjectByHandle","ObReferenceObjectByHandleWithTag"):
    va = found_imports.get(fname)
    if not va: continue
    sites = find_call_sites(va)
    print(f"\n  [{fname}] — {len(sites)} call site(s)")
    for caller, lineno, text in sites[:10]:
        # rcx=ProcessHandle, rdx=DesiredAccess, r8=ObjectType, r9=AccessMode
        # r8 = 0 means NO type check → any kernel object accepted → type confusion
        ctx = DISASM[max(0,lineno-15): lineno+2]
        ctx_text = "".join(ctx)
        # check if r8 (ObjectType) is set to 0 / xor r8d,r8d
        no_type = "xor    r8d,r8d" in ctx_text or "r8,0x0" in ctx_text
        print(f"    {'** TYPE=NULL **' if no_type else '  '} 0x{caller:016x}: ObjectType={'NULL (dangerous)' if no_type else 'set'}")

# ── 8. MmMapIoSpace — physical memory exposure ────────────────────────────
print("\n" + "="*70)
print("[ioctlance] MmMapIoSpace — PHYSICAL MEMORY EXPOSURE")
print("="*70)
va = found_imports.get("MmMapIoSpace")
if va:
    sites = find_call_sites(va)
    print(f"  MmMapIoSpace called {len(sites)} time(s) — can expose arbitrary physical memory")
    for caller, lineno, text in sites[:10]:
        print(f"    0x{caller:016x}")
        for l in DISASM[max(0,lineno-5):lineno+3]: print("      " + l.rstrip())
else:
    print("  MmMapIoSpace NOT imported (good)")

# ── 9. RtlCopyMemory / memmove with user-controlled sizes ─────────────────
print("\n" + "="*70)
print("[ioctlance] BULK MEMORY COPY — MISSING BOUNDS CHECK CANDIDATES")
print("="*70)
for fname in ("RtlCopyMemory","memmove","memcpy","RtlMoveMemory","RtlCopyBytes"):
    va = found_imports.get(fname)
    if not va: continue
    sites = find_call_sites(va)
    print(f"\n  [{fname}] — {len(sites)} call site(s) (showing first 10 with risk flags)")
    for caller, lineno, text in sites[:10]:
        ctx = DISASM[max(0,lineno-12): lineno+2]
        ctx_text = "".join(ctx)
        # r8 = size param; look for it coming from user-read (movzx, mov from [user buf])
        has_movzx = "movzx" in ctx_text
        has_mul = "imul" in ctx_text or "mul " in ctx_text
        risk = []
        if has_movzx: risk.append("size from zero-extend (user input?)")
        if has_mul: risk.append("size via multiply (overflow?)")
        flag = "** " if risk else "   "
        print(f"    {flag}0x{caller:016x}: {', '.join(risk) if risk else 'no flags'}")

# ── 10. ZwQuerySystemInformation — info leak ──────────────────────────────
print("\n" + "="*70)
print("[ioctlance] ZwQuerySystemInformation — INFO LEAK CANDIDATES")
print("="*70)
va = found_imports.get("ZwQuerySystemInformation")
if va:
    sites = find_call_sites(va)
    print(f"  Called {len(sites)} time(s)")
    for caller, lineno, text in sites[:5]:
        print(f"    0x{caller:016x}")
else:
    print("  Not imported")

# ── Summary ────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("SUMMARY")
print("="*70)
print(f"  IOCTL codes found          : {len(ioctl_candidates)}")
print(f"  METHOD_NEITHER codes       : {len(METHOD_NEITHER_CODES)}")
print(f"  RequestorMode checks       : {len(req_mode_hits)}")
print(f"  ProbeForRead imported      : {'YES' if probe_read_va else 'NO'}")
print(f"  ProbeForWrite imported     : {'YES' if probe_write_va else 'NO'}")
print(f"  MmMapIoSpace imported      : {'YES' if found_imports.get('MmMapIoSpace') else 'NO'}")
print(f"  Device strings found       : {len(dev_strings)}")
print()
