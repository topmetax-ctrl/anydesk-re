"""
Deep analysis: Find the license type enum and all feature gates.
Focus on the vtable+0x90 calls and the license type comparisons.
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
md.detail = True

text_rp = sections[0][4]
text_rs = sections[0][3]
text_va = imgbase + sections[0][2]

# Find all call [eax+0x90] and show context after each call
# to see what comparison follows (license type check)
pattern = b"\xff\x90\x90\x00\x00\x00"
pos = text_rp
results = []

while True:
    pos = b.find(pattern, pos)
    if pos < 0 or pos >= text_rp + text_rs:
        break
    ref_rva = file_to_rva(pos)
    if ref_rva is not None and ref_rva < sections[0][2] + sections[0][1]:
        call_va = imgbase + ref_rva
        # Disassemble 80 bytes after the call to see the comparison
        chunk = b[pos:pos + 80]
        insns = list(md.disasm(chunk, call_va))
        # Find the comparison pattern after the call
        cmp_info = []
        for insn in insns[:15]:
            if insn.mnemonic in ('sub', 'cmp', 'mov', 'test', 'je', 'jne', 'jz', 'jnz', 'ja', 'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle'):
                cmp_info.append(f"{insn.mnemonic} {insn.op_str}")
        results.append((call_va, cmp_info))
    pos += 1

print(f"=== {len(results)} call [eax+0x90] sites with following comparison ===\n")
for va, cmps in results:
    print(f"  0x{va:08x}:")
    for c in cmps[:6]:
        print(f"    {c}")
    print()

# Now find the license type setter - where is the license type stored?
# Search for mov [reg+0x98], imm or mov [reg+offset], eax patterns
# The object at [ebx+0x98] is the license manager
print("\n=== Searching for license type storage (mov [reg+0x98]) ===")
# Pattern: 89 ?? 98 00 00 00
for i in range(text_rs - 6):
    if b[text_rp + i] == 0x89:
        modrm = b[text_rp + i + 1]
        # Check for disp32 mode (mod=10, rm=101)
        if (modrm & 0xC7) == 0x80 or (modrm & 0xC7) == 0x81:
            disp = struct.unpack_from('<I', b, text_rp + i + 2)[0] if (modrm & 0xC0) == 0x80 else 0
            if disp == 0x98:
                va = text_va + i
                # Disassemble this instruction
                chunk = b[text_rp + i:text_rp + i + 20]
                for insn in md.disasm(chunk, va):
                    print(f"  0x{va:08x}: {insn.mnemonic} {insn.op_str}")
                    break

# Find the license type enum values by looking at the switch table
# At 0x10626bbb: sub eax,0; je / sub eax,1; je / sub eax,2; je
# This means values 0,1,2,3+ (default)
# Let's find what strings are associated with each case
print("\n=== License type enum analysis ===")
# case_0 (0x10627341): pushes 0x119463b8
# case_1 (0x10627324): pushes 0x11946400
# case_2 (0x106272bb): calls vtable+0x94
# default: countdown logic, pushes 0x11946440 and 0x119463dc

# Let's read the strings at those addresses
for label, str_va in [("case_0", 0x119463b8), ("case_1", 0x11946400), ("default_1", 0x11946440), ("default_2", 0x119463dc)]:
    str_foff = rva_to_file(str_va - imgbase)
    if str_foff:
        # Read the string key at this address
        s = b[str_foff:str_foff + 80]
        null_pos = s.find(b'\x00')
        if null_pos > 0:
            s = s[:null_pos]
        print(f"  {label} -> 0x{str_va:x}: {s.decode('latin1','replace')}")

# Find the premium dialog trigger function
# Search for references to ad.dlg.premium.title English string
print("\n=== Premium dialog references ===")
key = b"ad.dlg.premium.title="
pos = 0
while True:
    pos = b.find(key, pos)
    if pos < 0:
        break
    # Check if English
    val_start = pos + len(key)
    val = b[val_start:val_start + 40]
    if val and not any(c in val[:10] for c in b'\xc3\xc2\xc5'):
        rva = file_to_rva(pos)
        va = imgbase + rva if rva else 0
        print(f"  String at 0x{va:x}: {val[:40].decode('latin1','replace')}")
        # Search for VA references
        va_bytes = struct.pack('<I', va)
        pos2 = 0
        while True:
            pos2 = b.find(va_bytes, pos2)
            if pos2 < 0:
                break
            ref_rva = file_to_rva(pos2)
            if ref_rva is not None and ref_rva < sections[0][2] + sections[0][1]:
                print(f"    Code ref: 0x{imgbase+ref_rva:08x}")
            pos2 += 1
    pos += 1

# Find conn_limit references
print("\n=== Connection limit references ===")
key = b"ad.dlg.closed.license_conn_limit.message="
pos = 0
while True:
    pos = b.find(key, pos)
    if pos < 0:
        break
    val_start = pos + len(key)
    val = b[val_start:val_start + 60]
    if val and val[0:1] in (b'Y', b'H', b'U'):  # English starts
        rva = file_to_rva(pos)
        va = imgbase + rva if rva else 0
        print(f"  String at 0x{va:x}: {val[:60].decode('latin1','replace')}")
        va_bytes = struct.pack('<I', va)
        pos2 = 0
        while True:
            pos2 = b.find(va_bytes, pos2)
            if pos2 < 0:
                break
            ref_rva = file_to_rva(pos2)
            if ref_rva is not None and ref_rva < sections[0][2] + sections[0][1]:
                print(f"    Code ref: 0x{imgbase+ref_rva:08x}")
            pos2 += 1
    pos += 1
