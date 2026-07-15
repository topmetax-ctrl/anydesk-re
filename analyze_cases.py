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

# Disassemble case_0, case_1, case_2 targets
for name, va in [("case_0", 0x10627341), ("case_1", 0x10627324), ("case_2", 0x106272bb)]:
    foff = va_to_foff(va)
    chunk = b[foff:foff + 80]
    print(f"\n=== {name} at 0x{va:x} ===")
    for insn in md.disasm(chunk, va):
        print(f"  0x{insn.address:x}: {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}")
        if insn.mnemonic in ('ret', 'retn', 'jmp') and insn.address > va + 5:
            break
        if insn.address > va + 60:
            break

# Also look at what calls the countdown function (0x10626b70)
# Search for calls to 0x10626b70
text_start = sections[0][4]
text_end = text_start + sections[0][3]
target_va = 0x10626b70
print(f"\n=== Callers of countdown function 0x{target_va:x} ===")
callers = []
for i in range(text_start, text_end - 5):
    if b[i] == 0xe8:
        rel32 = struct.unpack_from('<i', b, i + 1)[0]
        call_va = i - text_start + imgbase + sections[0][2]
        dest = call_va + 5 + rel32
        if dest == target_va:
            callers.append(call_va)

print(f"Found {len(callers)} callers")
for c in callers:
    # Show context around caller
    ctx_foff = va_to_foff(c - 30)
    ctx_va = c - 30
    chunk = b[ctx_foff:ctx_foff + 60]
    print(f"\n  Caller at 0x{c:x}:")
    for insn in md.disasm(chunk, ctx_va):
        marker = " <--- CALL" if insn.address == c else ""
        print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
        if insn.address > c + 10:
            break
