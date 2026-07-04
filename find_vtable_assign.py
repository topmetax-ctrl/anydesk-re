"""
Find the actual license type getter by tracing the vtable used at 0x10626ba2.
The license manager object is at [ebx+0x98]. We need to find what vtable
is assigned to this object. Search for mov [reg+0x98], <vtable_ptr> or
mov [reg], <vtable_ptr> where reg comes from [ebx+0x98].

Also: search for the config key 0xd getter more carefully.
The fallback at 0x10626baa calls 0x1069af59 with push 0xd.
Let's trace what 0x1069af59 does.
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

# The key insight: at 0x10626ba2, call [eax+0x90] returns license type
# eax = [ecx] = vtable of the license manager object
# The license manager is at [ebx+0x98]
# ebx = 'this' pointer of the session/connection manager

# Let's search for where [ebx+0x98] is SET (mov [ebx+0x98], something)
# Pattern: 89 ?? 98 00 00 00
text_rp = sections[0][3]; text_rs = sections[0][2]; text_va = imgbase + sections[0][1]

print("=== Searching for mov [reg+0x98], <value> ===")
for i in range(text_rs - 6):
    if b[text_rp + i] == 0x89:
        modrm = b[text_rp + i + 1]
        # disp32: mod=10 (0x80), rm != 100
        if (modrm & 0xC0) == 0x80:
            disp = struct.unpack_from('<I', b, text_rp + i + 2)[0]
            if disp == 0x98:
                va = text_va + i
                foff = text_rp + i
                chunk = b[foff:foff+20]
                for insn in md.disasm(chunk, va):
                    if insn.mnemonic == 'mov' and '0x98' in insn.op_str:
                        # Check if source is a .rdata address (vtable)
                        if '0x11' in insn.op_str:
                            print(f"  0x{va:08x}: {insn.mnemonic} {insn.op_str}")
                    break

# Also search for mov [edi+0x98] / mov [esi+0x98] etc with vtable addr
print("\n=== Broader search: mov [reg+0x98], imm32 where imm in .rdata ===")
for i in range(text_rs - 10):
    # c7 ?? 98 00 00 00 <imm32> = mov dword ptr [reg+0x98], imm32
    if b[text_rp + i] == 0xc7:
        modrm = b[text_rp + i + 1]
        if (modrm & 0xC0) == 0x80:
            disp = struct.unpack_from('<I', b, text_rp + i + 2)[0]
            if disp == 0x98:
                imm = struct.unpack_from('<I', b, text_rp + i + 6)[0]
                # Check if imm is in .rdata
                rdata_va = imgbase + sections[1][1]
                rdata_end = rdata_va + sections[1][2]
                if rdata_va <= imm < rdata_end:
                    va = text_va + i
                    print(f"  0x{va:08x}: mov dword ptr [reg+0x98], 0x{imm:x} (VTABLE!)")
                    # Read the vtable entry at +0x90
                    vt_foff = r2f(imm - imgbase)
                    if vt_foff:
                        entry_90 = struct.unpack_from('<I', b, vt_foff + 0x90)[0]
                        print(f"    vtable[0x90] = 0x{entry_90:x}")
                        # Disassemble that function
                        func_foff = r2f(entry_90 - imgbase)
                        if func_foff:
                            chunk = b[func_foff:func_foff+80]
                            print(f"    Function at 0x{entry_90:x}:")
                            for insn in md.disasm(chunk, entry_90):
                                print(f"      0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
                                if insn.mnemonic in ('ret', 'ret') or insn.address > entry_90 + 50:
                                    break

# Also look at the second call site at 0x10627a62 which also calls [eax+0x90]
# and falls back to 0x1069be19 (different config getter)
print("\n=== Config getter at 0x1069be19 (second fallback) ===")
foff = r2f(0x1069be19 - imgbase)
if foff:
    chunk = b[foff:foff+200]
    for insn in md.disasm(chunk, 0x1069be19):
        print(f"  0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic in ('ret', 'ret') or insn.address > 0x1069be19 + 100:
            break
