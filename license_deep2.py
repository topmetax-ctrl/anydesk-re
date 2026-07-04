"""
Find the premium dialog trigger and connection limit check functions.
Disassemble around the English string references.
"""
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

def rva_to_file(rva):
    for nm, vs, va, rs, rp in sections:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)

# English premium title string at 0x113710ce
# English license_conn_limit message at 0x1136d1d1
# Find code refs to these
targets = {
    "premium_title": 0x113710ce,
    "conn_limit_msg": 0x1136d1d1,
}

for name, str_va in targets.items():
    va_bytes = struct.pack('<I', str_va)
    pos = 0
    refs = []
    while True:
        pos = b.find(va_bytes, pos)
        if pos < 0:
            break
        ref_rva = file_to_rva(pos)
        if ref_rva is not None and ref_rva < sections[0][2] + sections[0][1]:
            refs.append((pos, imgbase + ref_rva))
        pos += 1
    print(f"\n{'='*70}")
    print(f"=== {name} (0x{str_va:x}): {len(refs)} code refs ===")
    print(f"{'='*70}")
    for foff, va in refs:
        # Disassemble 200 bytes before and 100 after
        start = max(0, foff - 200)
        end = min(len(b), foff + 100)
        chunk = b[start:end]
        start_va = imgbase + file_to_rva(start)
        print(f"\n  Ref at 0x{va:08x}:")
        for insn in md.disasm(chunk, start_va):
            marker = " <--- REF" if insn.address == va else ""
            # Only show interesting instructions
            if insn.mnemonic in ('call', 'jmp', 'je', 'jne', 'jz', 'jnz', 'ret', 'retn') or \
               'push' in insn.mnemonic and '0x' in insn.op_str or \
               'cmp' in insn.mnemonic or 'sub' in insn.mnemonic and 'eax' in insn.op_str or \
               marker:
                print(f"    0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}{marker}")

# Also find the function that shows premium dialog
# Search for "ad.dlg.premium" key string references
print(f"\n{'='*70}")
print("=== Searching for premium dialog function ===")
print(f"{'='*70}")

# The premium dialog is likely triggered by a function that checks license
# and if not sufficient, shows the dialog. Let's find the function that
# references the premium title string and disassemble its beginning

# Find the function start by looking backwards from the ref
for name, str_va in [("premium_title", 0x113710ce)]:
    va_bytes = struct.pack('<I', str_va)
    pos = 0
    while True:
        pos = b.find(va_bytes, pos)
        if pos < 0:
            break
        ref_rva = file_to_rva(pos)
        if ref_rva is not None and ref_rva < sections[0][2] + sections[0][1]:
            ref_va = imgbase + ref_rva
            # Search backwards for function prologue (push ebp; mov ebp, esp = 55 8b ec)
            for offset in range(1, 500):
                if b[pos - offset:pos - offset + 3] == b'\x55\x8b\xec':
                    func_va = ref_va - offset
                    func_foff = pos - offset
                    print(f"  Function start: 0x{func_va:08x} (foff=0x{func_foff:x})")
                    # Disassemble first 100 bytes
                    chunk = b[func_foff:func_foff + 100]
                    for insn in md.disasm(chunk, func_va):
                        print(f"    0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
                        if insn.mnemonic == 'ret' or insn.address > func_va + 80:
                            break
                    break
        pos += 1
