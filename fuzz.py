#!/usr/bin/env python3
"""
dxgkrnl_fuzzer.py — Auto-generated IOCTL fuzzer
Driver  : dxgkrnl.sys  v10.0.19041.6456
Device  : DISPLAY
IOCTLs  : 44 discovered codes
Generated: 2026-08-27 08:17
Tool    : kernel_driver_analyze.py v4.0

Requirements:
  - Windows (run in VM with kernel debugger attached)
  - Run as Administrator
  - WinDbg attached: $$><dxgkrnl_windbg.wds  (auto-sets breakpoints)

Usage:
  python3 dxgkrnl_fuzzer.py [options]
  --device  DEVICENAME   Override device name (default: DISPLAY)
  --ioctls  0x1234,0x..  Comma-separated subset of IOCTLs to fuzz
  --rounds  N            Mutations per IOCTL (default: 20)
  --log     FILE         CSV log output (default: dxgkrnl_fuzz_log.csv)
  --size    N            Max buffer size in bytes (default: 0x1000)
  --seed    N            Random seed for reproducibility
"""
import ctypes, ctypes.wintypes as wt, struct, random, time, csv, sys, os, argparse

# ── Parse args ───────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(description="IOCTL Fuzzer for dxgkrnl.sys")
ap.add_argument("--device",  default=r"\\.\\ DISPLAY")
ap.add_argument("--ioctls",  default="")
ap.add_argument("--rounds",  type=int, default=20)
ap.add_argument("--log",     default="dxgkrnl_fuzz_log.csv")
ap.add_argument("--size",    type=int, default=0x1000)
ap.add_argument("--seed",    type=int, default=None)
args = ap.parse_args()
if args.seed: random.seed(args.seed)

# ── Windows API setup ────────────────────────────────────────────────────
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wt.HANDLE
k32.CreateFileW.argtypes = [wt.LPCWSTR,wt.DWORD,wt.DWORD,ctypes.c_void_p,wt.DWORD,wt.DWORD,wt.HANDLE]
k32.DeviceIoControl.restype = wt.BOOL
k32.DeviceIoControl.argtypes = [wt.HANDLE,wt.DWORD,ctypes.c_void_p,wt.DWORD,
                                  ctypes.c_void_p,wt.DWORD,ctypes.POINTER(wt.DWORD),ctypes.c_void_p]
k32.CloseHandle.argtypes = [wt.HANDLE]
INVALID_HANDLE = ctypes.cast(-1, wt.HANDLE)
GENERIC_RW     = 0xC0000000
FILE_SHARE_RW  = 0x3
OPEN_EXISTING  = 0x3

# ── IOCTL table (discovered by kernel_driver_analyze.py) ─────────────────
IOCTLS = [
    (0x00226044, "BUFFERED"),
    (0x0022644C, "BUFFERED"),
    (0x00226454, "BUFFERED"),
    (0x00230007, "NEITHER"),
    (0x00230800, "BUFFERED"),
    (0x00230804, "BUFFERED"),
    (0x00230808, "BUFFERED"),
    (0x0023080C, "BUFFERED"),
    (0x00230810, "BUFFERED"),
    (0x00230C00, "BUFFERED"),
    (0x00230C18, "BUFFERED"),
    (0x00231000, "BUFFERED"),
    (0x0023200F, "NEITHER"),
    (0x0023204F, "NEITHER"),
    (0x00232053, "NEITHER"),
    (0x00232063, "NEITHER"),
    (0x00232403, "NEITHER"),
    (0x00232407, "NEITHER"),
    (0x0023241F, "NEITHER"),
    (0x00232423, "NEITHER"),
    (0x0023242F, "NEITHER"),
    (0x00232433, "NEITHER"),
    (0x00232437, "NEITHER"),
    (0x00232483, "NEITHER"),
    (0x00232487, "NEITHER"),
    (0x0023248B, "NEITHER"),
    (0x0023248F, "NEITHER"),
    (0x00232493, "NEITHER"),
    (0x0023249B, "NEITHER"),
    (0x0023249F, "NEITHER"),
    (0x002324A3, "NEITHER"),
    (0x002324CF, "NEITHER"),
    (0x0023CC04, "BUFFERED"),
    (0x0023E057, "NEITHER"),
    (0x80000004, "BUFFERED"),
    (0x80000005, "IN_DIRECT"),
    (0x80000006, "OUT_DIRECT"),
    (0x80000008, "BUFFERED"),
    (0x80000010, "BUFFERED"),
    (0x80000011, "IN_DIRECT"),
    (0x8000001A, "OUT_DIRECT"),
    (0x80000020, "BUFFERED"),
    (0x80000022, "OUT_DIRECT"),
    (0x80000025, "IN_DIRECT")
]
if args.ioctls:
    subset = set(int(x,16) for x in args.ioctls.split(","))
    IOCTLS = [(c,m) for c,m in IOCTLS if c in subset]

# ── Mutation strategies ───────────────────────────────────────────────────
def mutate(method, sz, rng):
    """Generate a fuzzed buffer for the given method and size."""
    strats = [
        lambda: bytes(sz),                                    # all zeros
        lambda: bytes([0xff]*sz),                             # all 0xFF
        lambda: bytes([0x41]*sz),                             # all 0x41 (AAAA)
        lambda: rng.randbytes(sz),                            # random
        lambda: struct.pack("<Q", 0xdeadbeefcafebabe) * (sz//8+1)[:sz],  # magic ptr
        lambda: struct.pack("<Q", 0xffffffffffffffff) * (sz//8+1)[:sz],  # max
        lambda: struct.pack("<I", 0x7fffffff) * (sz//4+1)    # max signed int * N
    ]
    # METHOD_NEITHER needs special care — buf IS the user VA
    if method == "NEITHER":
        # also include near-NULL and kernel-VA-shaped values
        strats += [
            lambda: struct.pack("<Q", 1) + bytes(sz-8),      # near-NULL ptr
            lambda: struct.pack("<Q", 0xfffff80000000000) + bytes(sz-8),  # kernel VA
        ]
    buf = rng.choice(strats)()
    return (buf + bytes(sz))[:sz]

# ── Fuzzing loop ──────────────────────────────────────────────────────────
def fuzz(device_path):
    print(f"[*] Opening {device_path} ...")
    h = k32.CreateFileW(device_path, GENERIC_RW, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None)
    if h == INVALID_HANDLE:
        print(f"[-] CreateFile failed: {ctypes.get_last_error()}"); return

    print(f"[+] Device opened.  {len(IOCTLS)} IOCTLs × {args.rounds} rounds")
    print(f"    Log → {args.log}")
    rng = random.Random(args.seed)
    results = []
    total = 0

    for code, method in IOCTLS:
        for rnd in range(args.rounds):
            sz       = rng.choice([0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,args.size])
            inbuf    = mutate(method, sz, rng)
            outbuf   = (ctypes.c_ubyte * args.size)()
            returned = wt.DWORD(0)
            in_ptr   = (ctypes.c_ubyte * sz)(*inbuf)
            t0       = time.perf_counter()
            ok       = k32.DeviceIoControl(h, code, in_ptr, sz,
                                            outbuf, args.size, ctypes.byref(returned), None)
            elapsed  = time.perf_counter() - t0
            err      = ctypes.get_last_error()
            status   = "OK" if ok else f"ERR_{err}"
            results.append({"ioctl":hex(code),"method":method,"in_sz":sz,
                              "round":rnd,"status":status,"ret_bytes":returned.value,
                              "ms":round(elapsed*1000,2)})
            total += 1
            if rnd == 0:
                print(f"  IOCTL {hex(code)} [{method}]  round=0  {status}  "
                      f"ret={returned.value}B  {elapsed*1000:.1f}ms")

    k32.CloseHandle(h)

    # Write CSV log
    with open(args.log,"w",newline="") as f:
        w = csv.DictWriter(f,fieldnames=results[0].keys())
        w.writeheader(); w.writerows(results)

    # Summary
    by_ioctl = {}
    for r in results:
        c = r["ioctl"]
        by_ioctl.setdefault(c,{"ok":0,"err":0,"codes":set()})
        if r["status"]=="OK": by_ioctl[c]["ok"]+=1
        else:
            by_ioctl[c]["err"]+=1
            by_ioctl[c]["codes"].add(r["status"])
    print(f"\n[*] {total} total requests.  Results:")
    for c,(v) in sorted(by_ioctl.items()):
        flags = " ← ALL ERRORS" if v["ok"]==0 else (" ← MIXED" if v["err"]>0 else "")
        print(f"  {c}: {v['ok']} OK  {v['err']} ERR  {','.join(v['codes'])}{flags}")
    print(f"\n[+] Done. Log: {args.log}")

if __name__ == "__main__":
    fuzz(args.device)
