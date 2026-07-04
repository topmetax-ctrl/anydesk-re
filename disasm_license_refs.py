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

refs = [
    ("premium_title_1",   0x10670782),
    ("premium_title_2",   0x106ea90a),
    ("license_conn_limit",0x106c94a0),
    ("conn_limit",        0x10736053),
    ("session_queue_1",   0x1081bf10),
    ("session_queue_2",   0x1090d617),
    ("abook_limit",       0x108c3031),
    ("screen_record",     0x105c3f5c),
    ("session_invite",    0x10727c83),
]

for name, ref_va in refs:
    ref_foff = r2f(ref_va - imgbase)
    # Find function start (55 8b ec = push ebp; mov ebp,esp)
    func_start = None
    for off in range(1, 600):
        if b[ref_foff - off:ref_foff - off + 3] == b'\x55\x8b\xec':
            func_start = ref_va - off
            break

    start = max(0, ref_foff - 300)
    end = min(len(b), ref_foff + 80)
    chunk = b[start:end]
    start_va = imgbase + f2r(start)

    print(f"\n{'='*70}")
    print(f"=== {name} at 0x{ref_va:08x} (func_start={'0x%08x'%func_start if func_start else '?'}) ===")
    print(f"{'='*70}")

    for insn in md.disasm(chunk, start_va):
        marker = " <--- REF" if insn.address == ref_va else ""
        if insn.mnemonic in ('call','jmp','je','jne','jz','jnz','ret','retn','ja','jae','jb','jbe','jg','jge','jl','jle') or \
           ('push' in insn.mnemonic and '0x' in insn.op_str) or \
           ('cmp' in insn.mnemonic) or ('sub' in insn.mnemonic and 'eax' in insn.op_str) or \
           ('test' in insn.mnemonic) or marker:
            print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}{marker}")
