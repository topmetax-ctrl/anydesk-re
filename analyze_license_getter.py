"""
Analyze the license type getter at 0x106cbde0 (vtable+0x90 of vtable 0x1195bf8c).
This is the function that returns the license type enum.
Also find the premium dialog check function and all feature gates.
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

md = Cs(CS_ARCH_X86, CS_MODE_32)

# License type getter at 0x106cbde0
print("=== License type getter at 0x106cbde0 ===")
foff = r2f(0x106cbde0 - imgbase)
chunk = b[foff:foff+500]
for insn in md.disasm(chunk, 0x106cbde0):
    print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
    if insn.mnemonic == 'ret' and insn.address > 0x106cbde0 + 20:
        break

# Also check what the vtable 0x1195bf8c looks like
print("\n=== Vtable at 0x1195bf8c (first 0x98 bytes = 38 entries) ===")
vt_foff = r2f(0x1195bf8c - imgbase)
for i in range(0, 0x98, 4):
    val = struct.unpack_from('<I', b, vt_foff + i)[0]
    print(f"  [+0x{i:02x}] = 0x{val:08x}")

# Find all callers of 0x106cbde0
print("\n=== Direct callers of license getter 0x106cbde0 ===")
text_rp = sections[0][3]; text_rs = sections[0][2]; text_va = imgbase + sections[0][1]
target = 0x106cbde0
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
    print(f"    0x{va:08x}")

# Also find indirect callers via vtable 0x1195bf8c
# Search for the vtable address being assigned
print("\n=== Where vtable 0x1195bf8c is assigned ===")
vt_bytes = struct.pack('<I', 0x1195bf8c)
pos = 0
while True:
    pos = b.find(vt_bytes, pos)
    if pos < 0: break
    rva = None
    for vs, va, rs, rp in sections:
        if rp <= pos < rp + rs:
            rva = va + (pos - rp)
            break
    if rva and rva < sections[0][1] + sections[0][0]:
        print(f"  0x{imgbase+rva:08x} (foff=0x{pos:x})")
    pos += 1
