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

# Search for function addresses as 4-byte values (vtable entries)
targets = {
    0x1084e520: "banner_formatter",
    0x106c35b0: "banner_constructor",
    0x10626b70: "countdown_handler",
}

print("=== Searching for function addresses in data (vtables) ===")
for target_va, name in targets.items():
    target_bytes = struct.pack('<I', target_va)
    pos = 0
    refs = []
    while True:
        pos = b.find(target_bytes, pos)
        if pos < 0:
            break
        ref_rva = file_to_rva(pos)
        section_name = "?"
        for nm, vs, va, rs, rp in sections:
            if rp <= pos < rp + rs:
                section_name = nm
                break
        refs.append((pos, ref_rva, section_name))
        pos += 1
    print(f"  {name} (0x{target_va:x}): {len(refs)} refs")
    for foff, rva, sec in refs[:10]:
        va = imgbase + rva if rva else 0
        print(f"    foff=0x{foff:x} rva=0x{rva:x} va=0x{va:x} section={sec}")

# Now disassemble around SetWaitableTimer call (the countdown timer)
print("\n=== SetWaitableTimer call context ===")
md = Cs(CS_ARCH_X86, CS_MODE_32)
# call at 0x10abb5f2
foff = 0xaba9f2
start = foff - 200
chunk = b[start:foff+50]
start_va = imgbase + file_to_rva(start)
for insn in md.disasm(chunk, start_va):
    marker = " <--- SetWaitableTimer" if insn.address == 0x10abb5f2 else ""
    print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}{marker}")

# Also look at the countdown function more carefully
# Find the function that calls the countdown handler
# The countdown handler at 0x10626b70 - search for its address
print("\n=== Countdown handler vtable refs ===")
target_bytes = struct.pack('<I', 0x10626b70)
pos = 0
while True:
    pos = b.find(target_bytes, pos)
    if pos < 0:
        break
    ref_rva = file_to_rva(pos)
    sec = "?"
    for nm, vs, va, rs, rp in sections:
        if rp <= pos < rp + rs:
            sec = nm
            break
    print(f"  foff=0x{pos:x} rva=0x{ref_rva:x} va=0x{imgbase+ref_rva:x} sec={sec}")
    pos += 1

# Also search for the banner constructor address
print("\n=== Banner constructor vtable refs ===")
target_bytes = struct.pack('<I', 0x106c35b0)
pos = 0
while True:
    pos = b.find(target_bytes, pos)
    if pos < 0:
        break
    ref_rva = file_to_rva(pos)
    sec = "?"
    for nm, vs, va, rs, rp in sections:
        if rp <= pos < rp + rs:
            sec = nm
            break
    print(f"  foff=0x{pos:x} rva=0x{ref_rva:x} va=0x{imgbase+ref_rva:x} sec={sec}")
    pos += 1

# Search for banner formatter address
print("\n=== Banner formatter vtable refs ===")
target_bytes = struct.pack('<I', 0x1084e520)
pos = 0
while True:
    pos = b.find(target_bytes, pos)
    if pos < 0:
        break
    ref_rva = file_to_rva(pos)
    sec = "?"
    for nm, vs, va, rs, rp in sections:
        if rp <= pos < rp + rs:
            sec = nm
            break
    print(f"  foff=0x{pos:x} rva=0x{ref_rva:x} va=0x{imgbase+ref_rva:x} sec={sec}")
    pos += 1
