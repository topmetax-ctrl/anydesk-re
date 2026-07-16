"""
Analyze crash site and backtrace from AnyDesk crash log.
Crash: access violation 0xc0000005 at 0x00AE585F (RVA 0x185F)
Backtrace RVAs (image-relative) -> VA = RVA + 0x10000000
"""
import struct
from capstone import *

b = open("/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_inner.exe","rb").read()
e = struct.unpack_from('<I', b, 0x3C)[0]
coff = e + 4; nsec = struct.unpack_from('<H', b, coff+2)[0]
optsz = struct.unpack_from('<H', b, coff+16)[0]
opt = coff + 20; imgbase = struct.unpack_from('<I', b, opt+28)[0]
sec_off = opt + optsz; sections = []
for i in range(nsec):
    s = sec_off + i*40
    vs, va, rs, rp = struct.unpack_from('<IIII', b, s+8)
    sections.append((vs, va, rs, rp))

def r2f(rva):
    for vs, va, rs, rp in sections:
        if va <= rva < va + max(vs, rs): return rp + (rva - va)
    return None

def va2f(va): return r2f(va - imgbase)

md = Cs(CS_ARCH_X86, CS_MODE_32)

# New crash backtrace (RVA -> VA = RVA + 0x10000000)
# Crash: 0xc0000005 at 0x00AE585F (image base ~0x00AE4000, RVA 0x185F)
bt_rvas = [0x0000185f, 0x0000185f, 0x0084039c, 0x005ca40a, 0x008002d6,
           0x007fdd9c, 0x007fdd00, 0x00fccf72, 0x00fcc97b]

print("=== Crash backtrace analysis ===\n")
for i, rva in enumerate(bt_rvas):
    va = imgbase + rva
    foff = r2f(rva)
    if foff is None:
        print(f"  [{i}] RVA=0x{rva:08x} VA=0x{va:08x} - NOT IN IMAGE")
        continue
    
    # Check if this is at a patch site
    patch_info = ""
    for pva, pname in [(0x10626bbb,"countdown"), (0x10840537,"banner_skip"),
                       (0x10670788,"premium_dlg1"), (0x108c2f4b,"abook"),
                       (0x105c3f19,"rec1"), (0x105c3f32,"rec2"),
                       (0x10727b75,"invite"), (0x10645cd1,"timeout1"),
                       (0x10645d68,"timeout2")]:
        if abs(va - pva) < 0x200:
            patch_info = f" *** NEAR PATCH {pname} (0x{pva:x}, dist={abs(va-pva):#x}) ***"
    
    # Disassemble a few instructions at this address
    chunk = b[foff:foff+30]
    insns = list(md.disasm(chunk, va))
    if insns:
        insn = insns[0]
        print(f"  [{i}] VA=0x{va:08x}: {insn.mnemonic} {insn.op_str}{patch_info}")
    else:
        print(f"  [{i}] VA=0x{va:08x}: (undecodable){patch_info}")

# Disassemble crash site with more context
print("\n=== Crash site 0x1000185F (detailed) ===")
crash_va = 0x1000185f
foff = va2f(crash_va)
if foff:
    # Show 20 bytes before and 40 after
    start = max(0, foff - 40)
    start_va = crash_va - 40
    chunk = b[start:foff+40]
    for insn in md.disasm(chunk, start_va):
        marker = " <--- CRASH" if insn.address == crash_va else ""
        print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}{marker}")

# Check what's at the faulting address 0x00AE585F
# This is the actual memory address, image base is ~0x00AE4000
# RVA = 0x185F, VA in our analysis = 0x1000185F
print("\n=== Faulting address analysis ===")
print(f"  Crash at 0x00AE585F, image base ~0x00AE4000, RVA=0x185F")
print(f"  In our analysis: VA=0x1000185F")
foff = r2f(0x185F)
if foff:
    print(f"  In image at foff=0x{foff:x}")
    print(f"  Bytes: {b[foff:foff+16].hex(' ')}")
else:
    print(f"  NOT in image sections")

# Analyze the caller at 0x1084039C (near banner function)
print("\n=== Caller 0x1084039C (near banner func 0x10840500) ===")
caller_va = 0x1084039c
foff = va2f(caller_va)
if foff:
    # Find function start
    for offset in range(1, 8192):
        check = foff - offset
        if check < sections[0][3]:  # text raw offset
            break
        if b[check:check+3] == b'\x55\x8b\xec':
            func_start = caller_va - offset
            print(f"  Function start: 0x{func_start:08x}")
            # Show from function start to caller + 30
            chunk = b[check:foff+30]
            count = 0
            for insn in md.disasm(chunk, func_start):
                marker = " <--- BT FRAME" if insn.address == caller_va else ""
                print(f"    0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}{marker}")
                count += 1
                if count > 100:
                    print("    ... (truncated)")
                    break
            break

# Search for banner function 0x10840500 as a pointer (vtable entry)
print("\n=== Search for 0x10840500 as pointer in .rdata/.data ===")
target_bytes = struct.pack('<I', 0x10840500)
for sec_idx, sec_name in [(1, ".rdata"), (2, ".data")]:
    if sec_idx >= len(sections):
        continue
    sec_rp = sections[sec_idx][3]
    sec_rs = sections[sec_idx][2]
    pos = sec_rp
    while pos < sec_rp + sec_rs - 4:
        pos = b.find(target_bytes, pos, sec_rp + sec_rs)
        if pos < 0:
            break
        ref_rva = pos - sec_rp + sections[sec_idx][1]
        ref_va = imgbase + ref_rva
        print(f"  Found in {sec_name} at VA=0x{ref_va:08x}")
        # Show vtable context (8 pointers before and after)
        for j in range(-4, 5):
            ptr_off = pos + j * 4
            if ptr_off >= sec_rp and ptr_off + 4 <= sec_rp + sec_rs:
                ptr_val = struct.unpack_from('<I', b, ptr_off)[0]
                ptr_va = imgbase + (ptr_off - sec_rp + sections[sec_idx][1])
                marker = " <---" if j == 0 else ""
                print(f"    0x{ptr_va:08x}: 0x{ptr_val:08x}{marker}")
        pos += 1

# Also check what's at 0x1084039C - is it a call to banner function?
print("\n=== Check if 0x1084039C calls banner function ===")
foff = va2f(0x1084039c)
chunk = b[foff:foff+10]
for insn in md.disasm(chunk, 0x1084039c):
    print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic == 'call':
        # Check if it's calling 0x10840500
        if '0x10840500' in insn.op_str:
            print("  *** THIS CALLS THE BANNER FUNCTION! ***")
    break

# Check the crash site function - what does it do?
print("\n=== Crash site function 0x1000185F - find function start ===")
crash_foff = r2f(0x185F)
if crash_foff:
    for offset in range(1, 2048):
        check = crash_foff - offset
        if check < sections[0][3]:
            break
        if b[check:check+3] == b'\x55\x8b\xec':
            func_start_rva = 0x185F - offset
            func_start_va = imgbase + func_start_rva
            print(f"  Function start: 0x{func_start_va:08x} (RVA 0x{func_start_rva:x})")
            chunk = b[check:crash_foff+20]
            count = 0
            for insn in md.disasm(chunk, func_start_va):
                marker = " <--- CRASH" if insn.address == 0x1000185f else ""
                print(f"    0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}{marker}")
                count += 1
                if count > 50:
                    break
            break
