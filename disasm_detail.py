import struct
from capstone import *

b = open("/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_inner.exe","rb").read()
e = struct.unpack_from('<I', b, 0x3C)[0]
coff = e + 4
nsec = struct.unpack_from('<H', b, coff+2)[0]
optsz = struct.unpack_from('<H', b, coff+16)[0]
opt = coff + 20
imgbase = struct.unpack_from('<I', b, opt+28)[0]
sec_off = opt + optsz
sections = []
for i in range(nsec):
    s = sec_off + i*40
    nm = b[s:s+8].rstrip(b'\x00').decode('latin1','replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', b, s+8)
    sections.append((nm, vs, va, rs, rp))

def file_to_rva(foff):
    for nm, vs, va, rs, rp in sections:
        if rp <= foff < rp + rs:
            return va + (foff - rp)
    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)

def disasm_around(foff, before=400, after=200, label=""):
    rva = file_to_rva(foff)
    va = imgbase + rva
    start = max(0, foff - before)
    end = min(len(b), foff + after)
    chunk = b[start:end]
    start_va = imgbase + file_to_rva(start)

    print(f"\n{'='*80}")
    print(f"=== {label} at va=0x{va:x} (foff=0x{foff:x}) ===")
    print(f"{'='*80}")
    for insn in md.disasm(chunk, start_va):
        marker = " <--- REF" if insn.address == va else ""
        print(f"  0x{insn.address:08x}: {insn.bytes.hex():<34s} {insn.mnemonic:8s} {insn.op_str}{marker}")

# 1. disconnect_countdown refs (both close together)
disasm_around(0x626166, 400, 300, "disconnect_countdown_1")
disasm_around(0x626233, 50, 200, "disconnect_countdown_2")
