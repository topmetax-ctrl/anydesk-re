"""
Find the license type getter implementation.
1. Disassemble config getter 0x1069af59
2. Find vtable+0x90 implementations for license manager
3. Search for license type comparisons (cmp eax, 0/1/2/3)
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

def f2r(f):
    for vs, va, rs, rp in sections:
        if rp <= f < rp + rs: return va + (f - rp)
    return None

def r2f(rva):
    for vs, va, rs, rp in sections:
        if va <= rva < va + max(vs, rs): return rp + (rva - va)
    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)

# 1. Disassemble config getter at 0x1069af59
print("=== Config getter at 0x1069af59 ===")
foff = r2f(0x1069af59 - imgbase)
chunk = b[foff:foff+300]
for insn in md.disasm(chunk, 0x1069af59):
    print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
    if insn.mnemonic == 'ret' or insn.mnemonic == 'int3':
        break

# 2. The countdown handler calls [eax+0x90] on the license manager object
# The license manager is at [ebx+0x98]
# Let's find what vtable is assigned to the license manager
# Search for mov [reg+0x98], <vtable_addr> patterns
# Actually, search for mov dword ptr [reg], <addr> where addr is in .rdata (vtable)
print("\n=== Searching for vtable assignments to objects with +0x90 method ===")
# The vtable+0x90 means the vtable has at least 0x90/4 = 36 entries
# Let's find vtables in .rdata that have a function pointer at offset 0x90

# First, let's look at what the countdown handler does:
# mov ecx, [ebx + 0x98]  -> license manager object
# mov eax, [ecx]         -> vtable
# call [eax + 0x90]      -> get_license_type

# Search for the pattern: 8b ?? 98 00 00 00 (mov reg, [reg+0x98])
# followed by 8b 01 (mov eax, [ecx]) and ff 90 90 00 00 00 (call [eax+0x90])
text_rp = sections[0][3]; text_rs = sections[0][2]; text_va = imgbase + sections[0][1]

# Actually let's search for the exact byte sequence from the countdown handler:
# 8b 8b 98 00 00 00   mov ecx, [ebx + 0x98]
# 85 c9               test ecx, ecx
# 74 0a               je ...
# 8b 01               mov eax, [ecx]
# ff 90 90 00 00 00   call [eax + 0x90]
pattern = b"\x8b\x8b\x98\x00\x00\x00\x85\xc9"
pos = text_rp
sites = []
while True:
    pos = b.find(pattern, pos, text_rp + text_rs)
    if pos < 0: break
    rva = f2r(pos)
    if rva and rva < sections[0][1] + sections[0][0]:
        sites.append(imgbase + rva)
    pos += 1

print(f"\n  Found {len(sites)} sites with mov ecx,[ebx+0x98]; test ecx,ecx pattern:")
for va in sites[:10]:
    foff = r2f(va - imgbase)
    chunk = b[foff:foff+40]
    print(f"\n  At 0x{va:08x}:")
    for insn in md.disasm(chunk, va):
        print(f"    0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
        if insn.address > va + 30:
            break

# 3. Find the function that actually returns the license type
# The vtable+0x90 method is the getter. Let's find vtables in .rdata
# that have a function at offset 0x90
print("\n=== Searching for vtables with function at offset 0x90 ===")
rdata_rp = sections[1][3]; rdata_rs = sections[1][2]
rdata_va = imgbase + sections[1][1]

# A vtable is a sequence of function pointers in .rdata
# At offset 0x90 (entry 36), there should be a valid .text address
count = 0
for i in range(0, rdata_rs - 0x94, 4):
    # Check if this looks like a vtable start (first entry is a .text addr)
    first = struct.unpack_from('<I', b, rdata_rp + i)[0]
    if not (text_va <= first < text_va + text_rs):
        continue
    # Check entry at offset 0x90
    entry_90 = struct.unpack_from('<I', b, rdata_rp + i + 0x90)[0]
    if text_va <= entry_90 < text_va + text_rs:
        # Also check a few more entries to confirm it's a vtable
        valid = True
        for j in range(0, 0x94, 4):
            val = struct.unpack_from('<I', b, rdata_rp + i + j)[0]
            if not (text_va <= val < text_va + text_rs):
                valid = False
                break
        if valid:
            vt_va = rdata_va + i
            func_90_va = entry_90
            count += 1
            if count <= 15:
                print(f"  VTable at 0x{vt_va:08x}, [+0x90] = 0x{func_90_va:08x}")
                # Disassemble the function at +0x90
                func_foff = r2f(func_90_va - imgbase)
                if func_foff:
                    chunk = b[func_foff:func_foff+60]
                    print(f"    Function at 0x{func_90_va:08x}:")
                    for insn in md.disasm(chunk, func_90_va):
                        print(f"      0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
                        if insn.mnemonic in ('ret','ret') or insn.address > func_90_va + 40:
                            break

print(f"\n  Total vtables with valid +0x90: {count}")
