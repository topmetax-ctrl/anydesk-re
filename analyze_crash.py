"""
Analyze crash site and backtrace from AnyDesk crash log.
Crash: access violation 0xc0000005 at 0x00EBDBE0
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

# Backtrace addresses (RVA -> VA)
bt_rvas = [0x005b9be0, 0x0091a7f6, 0x0091b913, 0x00ad7a23, 0x00ad7e61,
           0x0091bd14, 0x0007611b, 0x00949797, 0x0007611b, 0x00ada12e,
           0x00072699, 0x00aea863, 0x00aea767, 0x00abba3d, 0x00abb9c5, 0x00abbb8a]

print("=== Crash backtrace analysis ===\n")
for i, rva in enumerate(bt_rvas):
    va = imgbase + rva
    foff = r2f(rva)
    if foff is None:
        print(f"  [{i}] RVA=0x{rva:08x} VA=0x{va:08x} - NOT IN IMAGE")
        continue
    
    # Check if this is at a patch site
    patch_info = ""
    for pva, pname in [(0x10626bbb,"countdown"), (0x106c376f,"banner_ui"), 
                       (0x1084e520,"banner_fmt"), (0x10670788,"premium_dlg1"),
                       (0x108c2f4b,"abook"), (0x105c3f19,"rec1"), 
                       (0x105c3f32,"rec2"), (0x10727b75,"invite")]:
        if abs(va - pva) < 0x100:
            patch_info = f" *** NEAR PATCH {pname} (0x{pva:x}) ***"
    
    # Disassemble a few instructions at this address
    chunk = b[foff:foff+30]
    insns = list(md.disasm(chunk, va))
    if insns:
        insn = insns[0]
        print(f"  [{i}] VA=0x{va:08x}: {insn.mnemonic} {insn.op_str}{patch_info}")
    else:
        print(f"  [{i}] VA=0x{va:08x}: (undecodable){patch_info}")

# Disassemble crash site with more context
print("\n=== Crash site 0x1005b9be0 (detailed) ===")
crash_va = 0x1005b9be0
foff = va2f(crash_va)
if foff:
    # Show 20 bytes before and 40 after
    start = max(0, foff - 40)
    start_va = crash_va - 40
    chunk = b[start:foff+40]
    for insn in md.disasm(chunk, start_va):
        marker = " <--- CRASH" if insn.address == crash_va else ""
        print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}{marker}")

# Check what's at 0x00EBDBE0 (the faulting address)
print("\n=== Faulting address 0x00EBDBE0 ===")
fault_rva = 0x00EBDBE0
foff = r2f(fault_rva)
if foff:
    print(f"  In image at foff=0x{foff:x}")
    print(f"  Bytes: {b[foff:foff+16].hex(' ')}")
else:
    print(f"  NOT in image sections (heap/stack address)")

# Check if banner_formatter_ret could cause issues
# The function at 0x1084e520 returns xor eax,eax; ret 0x10
# Let's find all callers of this function
print("\n=== Callers of banner_formatter (0x1084e520) ===")
target = 0x1084e520
text_rp = sections[0][3]; text_rs = sections[0][2]; text_va = imgbase + sections[0][1]
callers = []
for i in range(text_rs - 5):
    if b[text_rp + i] == 0xE8:
        rel = struct.unpack_from('<i', b, text_rp + i + 1)[0]
        call_va = text_va + i
        dest = call_va + 5 + rel
        if dest == target:
            callers.append(call_va)
print(f"  {len(callers)} direct callers")
for va in callers[:10]:
    # Show context around the call
    foff = va2f(va)
    chunk = b[max(0,foff-20):foff+30]
    start_va = va - 20
    print(f"\n  Caller at 0x{va:08x}:")
    for insn in md.disasm(chunk, start_va):
        marker = " <--- CALL" if insn.address == va else ""
        print(f"    0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}{marker}")
        if insn.address > va + 15:
            break
