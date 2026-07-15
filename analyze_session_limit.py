import struct
from capstone import *

b = open('/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_inner.exe','rb').read()

e = struct.unpack_from('<I', b, 0x3C)[0]
coff = e + 4
nsec = struct.unpack_from('<H', b, coff + 2)[0]
optsz = struct.unpack_from('<H', b, coff + 16)[0]
opt = coff + 20
imgbase = struct.unpack_from('<I', b, opt + 28)[0]
sec_off = opt + optsz
sections = []
for i in range(nsec):
    s = sec_off + i * 40
    nm = b[s:s+8].rstrip(b'\x00').decode('latin1','replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', b, s + 8)
    sections.append((nm, vs, va, rs, rp))

def va_to_foff(va):
    return va - imgbase - sections[0][2] + sections[0][4]

md = Cs(CS_ARCH_X86, CS_MODE_32)

# Disassemble the three case targets and the sessions.reconnect reference
targets = [
    ("case_0 (0x10627341)", 0x10627341, 100),
    ("case_1 (0x10627324)", 0x10627324, 50),
    ("case_2 (0x106272bb)", 0x106272bb, 50),
]

for name, va, size in targets:
    print(f"\n=== {name} ===")
    foff = va_to_foff(va)
    chunk = b[foff:foff + size]
    for insn in md.disasm(chunk, va):
        print(f"  0x{insn.address:x}: {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic in ('ret', 'retn') and insn.address > va + 10:
            break
        if insn.address > va + size:
            break

# Find xref to sessions.reconnect (0x11967b60)
print("\n=== Xref to 'sessions.reconnect' (0x11967b60) ===")
str_bytes = struct.pack('<I', 0x11967b60)
text_start = sections[0][4]
text_end = text_start + sections[0][3]
pos = text_start
while pos < text_end - 4:
    pos = b.find(str_bytes, pos, text_end)
    if pos < 0:
        break
    ref_va = pos - text_start + imgbase + sections[0][2]
    # Disassemble around this reference
    ctx_start = max(text_start, va_to_foff(ref_va - 40))
    ctx_va = ref_va - 40
    chunk = b[ctx_start:ctx_start + 80]
    for insn in md.disasm(chunk, ctx_va):
        marker = " <---" if insn.address <= ref_va < insn.address + insn.size else ""
        print(f"  0x{insn.address:x}: {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}{marker}")
        if insn.address > ref_va + 20:
            break
    pos += 1

# Find xref to 'session' (0x119735a0)
print("\n=== Xrefs to 'session' (0x119735a0) ===")
str_bytes = struct.pack('<I', 0x119735a0)
pos = text_start
while pos < text_end - 4:
    pos = b.find(str_bytes, pos, text_end)
    if pos < 0:
        break
    ref_va = pos - text_start + imgbase + sections[0][2]
    ctx_start = max(text_start, va_to_foff(ref_va - 30))
    ctx_va = ref_va - 30
    chunk = b[ctx_start:ctx_start + 60]
    for insn in md.disasm(chunk, ctx_va):
        marker = " <---" if insn.address <= ref_va < insn.address + insn.size else ""
        print(f"  0x{insn.address:x}: {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}{marker}")
        if insn.address > ref_va + 10:
            break
    print()
    pos += 1
