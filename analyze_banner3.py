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

def foff_to_va(foff):
    return foff + imgbase + sections[0][2] - sections[0][4]

text_start = sections[0][4]
text_end = text_start + sections[0][3]
rdata_start = sections[1][4]
rdata_end = rdata_start + sections[1][3]
md = Cs(CS_ARCH_X86, CS_MODE_32)

# 1. Disassemble banner function epilogue at 0x10841180
print("=== Banner function epilogue at 0x10841180 ===")
foff = va_to_foff(0x10841180)
chunk = b[foff:foff + 100]
for insn in md.disasm(chunk, 0x10841180):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic in ('ret', 'retn'):
        break

# 2. Check the first few bytes of banner function 0x10840500
print("\n=== Banner function 0x10840500 first bytes ===")
foff = va_to_foff(0x10840500)
print(f"  Raw: {b[foff:foff+10].hex()}")
for insn in md.disasm(b[foff:foff+30], 0x10840500):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")

# 3. Analyze function 0x10838550 (references license_banner_type)
print("\n=== Function 0x10838550 (license_banner_type ref) ===")
foff = va_to_foff(0x10838550)
chunk = b[foff:foff + 600]
for insn in md.disasm(chunk, 0x10838550):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic in ('ret', 'retn') and insn.address > 0x10838920:
        break
    if insn.address > 0x10838950:
        print("  ... (truncated)")
        break

# 4. Find SetTimer IAT entry
print("\n=== SetTimer IAT ===")
# Search for "SetTimer" string in rdata
pos = rdata_start
while pos < rdata_end:
    pos = b.find(b'SetTimer\x00', pos, rdata_end)
    if pos < 0:
        break
    va = foff_to_va(pos)
    print(f"  String at 0x{va:x}")
    pos += 1

# Search for "KillTimer" too
pos = rdata_start
while pos < rdata_end:
    pos = b.find(b'KillTimer\x00', pos, rdata_end)
    if pos < 0:
        break
    va = foff_to_va(pos)
    print(f"  KillTimer string at 0x{va:x}")
    pos += 1

# 5. Find all push 0xF4240 with 100 bytes context, look for any call to IAT
print("\n=== push 0xF4240 locations with wide context ===")
pattern = b'\x68\x40\x42\x0f\x00'
push_locs = []
pos = text_start
while pos < text_end - 5:
    pos = b.find(pattern, pos, text_end)
    if pos < 0:
        break
    ref_va = foff_to_va(pos)
    push_locs.append(ref_va)
    pos += 1

for loc in push_locs:
    foff = va_to_foff(loc - 30)
    chunk = b[foff:foff + 100]
    print(f"\n  --- 0x{loc:x} ---")
    for insn in md.disasm(chunk, loc - 30):
        marker = " <---" if insn.address == loc else ""
        print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
        if insn.address > loc + 50:
            break

# 6. Find callers of banner function 0x10840500 (both direct and indirect)
print("\n=== Callers of 0x10840500 ===")
target_va = 0x10840500
# Direct calls
callers = []
for i in range(text_start, text_end - 5):
    if b[i] == 0xe8:
        rel32 = struct.unpack_from('<i', b, i + 1)[0]
        call_va = foff_to_va(i)
        dest = call_va + 5 + rel32
        if dest == target_va:
            callers.append(call_va)
print(f"  Direct callers: {len(callers)}")
for c in callers:
    print(f"    0x{c:x}")

# Check if 0x10840500 appears as a pointer in .rdata or .data
target_bytes = struct.pack('<I', target_va)
print(f"\n  Searching for pointer 0x{target_va:x} in .rdata/.data...")
for sec_name, sec_vs, sec_va, sec_rs, sec_rp in sections[1:]:
    pos = sec_rp
    while pos < sec_rp + sec_rs - 4:
        pos = b.find(target_bytes, pos, sec_rp + sec_rs)
        if pos < 0:
            break
        ref_va = foff_to_va(pos)
        print(f"    Found at 0x{ref_va:x} (in {sec_name})")
        # Show surrounding context (vtable?)
        print(f"    Context: {b[pos-16:pos+20].hex()}")
        pos += 1

# 7. Check what's at 0x10d83764 more carefully - is this even in a function?
print("\n=== 0x10d83764 context (current bad patch) ===")
foff = va_to_foff(0x10d83764)
# Find function start
for offset in range(1, 2048):
    check = foff - offset
    if b[check:check+3] == b'\x55\x8b\xec':
        func_start = 0x10d83764 - offset
        print(f"  Function start: 0x{func_start:x}")
        chunk = b[check:check + 300]
        for insn in md.disasm(chunk, func_start):
            marker = " <--- BAD PATCH" if insn.address == 0x10d83764 else ""
            print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
            if insn.address > 0x10d83780:
                break
        break
