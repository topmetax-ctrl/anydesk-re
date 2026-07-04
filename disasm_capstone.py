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
md.detail = True

refs = [
    ("disconnect_countdown_1", 0x626166),
    ("disconnect_countdown_2", 0x626233),
    ("banner_free",            0x6c2b0f),
    ("banner_free_default",    0x84d9d2),
    ("netinfo_waiting",        0x731345),
    ("banner_expired",         0x84db1a),
    ("banner_expires",         0x84db01),
]

for name, foff in refs:
    rva = file_to_rva(foff)
    va = imgbase + rva
    # Disassemble 512 bytes before and 128 after
    start = max(0, foff - 512)
    end = min(len(b), foff + 128)
    chunk = b[start:end]
    start_va = imgbase + file_to_rva(start)

    print(f"\n{'='*80}")
    print(f"=== {name} at va=0x{va:x} (foff=0x{foff:x}) ===")
    print(f"{'='*80}")

    for insn in md.disasm(chunk, start_va):
        marker = " <--- REF" if insn.address == va else ""
        # Highlight calls, jumps, and the reference
        if insn.mnemonic in ('call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle', 'ja', 'jae', 'jb', 'jbe', 'js', 'jns', 'ret', 'retn') or marker:
            print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic} {insn.op_str}{marker}")
        elif 'push' in insn.mnemonic and '0x' in insn.op_str:
            print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic} {insn.op_str}{marker}")
