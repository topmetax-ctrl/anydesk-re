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

# Search for RVA values (VA - imgbase) in the binary
targets = {
    0x1084e520 - imgbase: "banner_formatter_RVA",
    0x106c35b0 - imgbase: "banner_constructor_RVA",
    0x10626b70 - imgbase: "countdown_handler_RVA",
    0x1084e520: "banner_formatter_VA",
    0x106c35b0: "banner_constructor_VA",
    0x10626b70: "countdown_handler_VA",
}

print(f"ImageBase = 0x{imgbase:x}")
print("=== Searching for function addresses (both VA and RVA) ===")
for target, name in targets.items():
    target_bytes = struct.pack('<I', target)
    pos = 0
    refs = []
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
        refs.append((pos, ref_rva, sec))
        pos += 1
    if refs:
        print(f"  {name} (0x{target:x}): {len(refs)} refs")
        for foff, rva, sec in refs[:10]:
            va = imgbase + rva if rva else 0
            print(f"    foff=0x{foff:x} rva=0x{rva:x} va=0x{va:x} sec={sec}")

# Also try: search for call rel32 instructions targeting these functions
# call rel32 = E8 xx xx xx xx where xx = target - (addr + 5)
print("\n=== Searching for direct call instructions (E8 rel32) ===")
text_rp = sections[0][4]
text_rs = sections[0][3]
text_va = imgbase + sections[0][2]

for target_va, name in [(0x1084e520, "banner_formatter"), (0x106c35b0, "banner_constructor"), (0x10626b70, "countdown_handler")]:
    found = []
    for i in range(text_rs - 5):
        if b[text_rp + i] == 0xE8:
            rel = struct.unpack_from('<i', b, text_rp + i + 1)[0]
            call_va = text_va + i
            dest = call_va + 5 + rel
            if dest == target_va:
                found.append(call_va)
    if found:
        print(f"  {name}: {len(found)} direct calls")
        for va in found:
            print(f"    call at 0x{va:08x}")
    else:
        print(f"  {name}: no direct calls found")

# Let's also look at what calls the function at 0x10626b70 region
# The function starts at 0x10626b70 but maybe it's called from nearby
# Let's look at the switch jump table at 0x10626bbb
print("\n=== Analyzing countdown function structure ===")
# The function at 0x10626b70 has a switch at 0x10626bbb:
# sub eax, 0 -> je 0x10627341
# sub eax, 1 -> je 0x10627324
# sub eax, 2 -> je 0x106272bb
# default -> countdown logic

# Let's look at what's at the jump targets
md = Cs(CS_ARCH_X86, CS_MODE_32)
for label, target_va in [("case_0", 0x10627341), ("case_1", 0x10627324), ("case_2", 0x106272bb)]:
    target_foff = rva_to_file(target_va - imgbase)
    if target_foff:
        chunk = b[target_foff:target_foff+80]
        print(f"\n  {label} at 0x{target_va:x}:")
        for insn in md.disasm(chunk, target_va):
            print(f"    0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
            if insn.mnemonic in ('ret', 'ret', 'jmp') and insn.address > target_va + 4:
                break
