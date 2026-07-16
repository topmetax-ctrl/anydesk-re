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
    print(f"  Section {i}: {nm:8s} VA=0x{imgbase+va:08x} VS=0x{vs:x} RP=0x{rp:x} RS=0x{rs:x}")

def va_to_foff(va):
    return va - imgbase - sections[0][2] + sections[0][4]

def foff_to_va(foff):
    return foff + imgbase + sections[0][2] - sections[0][4]

text_start = sections[0][4]
text_end = text_start + sections[0][3]
md = Cs(CS_ARCH_X86, CS_MODE_32)

# 1. Verify exact bytes at 0x10840537 (je -> jmp patch point)
print("\n=== Verify bytes at 0x10840537 ===")
foff = va_to_foff(0x10840537)
raw = b[foff:foff+6]
print(f"  Raw: {raw.hex()}")
print(f"  Expected: 0f84430c0000 (je 0x10841180)")
# Calculate jmp offset
# je: 0x10840537 + 6 + 0x0c43 = 0x10841180
# jmp: 0x10840537 + 5 + offset = 0x10841180 -> offset = 0x0c44
jmp_bytes = b'\xe9\x44\x0c\x00\x00\x90'
print(f"  Patch:   {jmp_bytes.hex()} (jmp 0x10841180 + nop)")

# 2. Check which section 0x111d2bd0 is in
print("\n=== Section for 0x111d2bd0 ===")
target_va = 0x111d2bd0
for i, (nm, vs, va, rs, rp) in enumerate(sections):
    sec_va_start = imgbase + va
    sec_va_end = sec_va_start + vs
    if sec_va_start <= target_va < sec_va_end:
        print(f"  In section {i}: {nm} (VA range: 0x{sec_va_start:08x}-0x{sec_va_end:08x})")

# 3. Search for SetTimer IAT 0x110af718 call sites
print("\n=== SetTimer IAT 0x110af718 call sites ===")
pattern = b'\xff\x15\x18\xf7\x0a\x11'
pos = text_start
callers = []
while pos < text_end - 6:
    pos = b.find(pattern, pos, text_end)
    if pos < 0:
        break
    call_va = foff_to_va(pos)
    callers.append(call_va)
    pos += 1
print(f"  Found {len(callers)} call sites")
for c in callers[:5]:
    ctx_foff = va_to_foff(c - 20)
    chunk = b[ctx_foff:ctx_foff + 40]
    print(f"  Call at 0x{c:x}:")
    for insn in md.disasm(chunk, c - 20):
        marker = " <---" if insn.address == c else ""
        print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
        if insn.address > c + 6:
            break

# 4. Also check what's at IAT 0x110af718 - is it really SetTimer?
print("\n=== Check IAT entry 0x110af718 ===")
iat_foff = va_to_foff(0x110af718)
# This should be in .rdata - check
for i, (nm, vs, va, rs, rp) in enumerate(sections):
    sec_foff_start = rp
    sec_foff_end = rp + rs
    if sec_foff_start <= iat_foff < sec_foff_end:
        print(f"  In section {i}: {nm}")
# The IAT entry contains a pointer to the actual function
iat_value = struct.unpack_from('<I', b, iat_foff)[0]
print(f"  IAT value: 0x{iat_value:08x}")

# 5. Check IAT entries around 0x110af718
print("\n=== IAT entries around 0x110af718 ===")
for offset in range(-8, 12, 4):
    addr = 0x110af718 + offset
    foff = va_to_foff(addr)
    val = struct.unpack_from('<I', b, foff)[0]
    print(f"  0x{addr:08x}: 0x{val:08x}")

# 6. Find all ff 15 calls in session timeout area (0x10645c00-0x10645e00)
print("\n=== Indirect calls in session timeout area ===")
for va_start, va_end in [(0x10645c00, 0x10645e00)]:
    foff_start = va_to_foff(va_start)
    foff_end = va_to_foff(va_end)
    chunk = b[foff_start:foff_end]
    for insn in md.disasm(chunk, va_start):
        if insn.mnemonic == 'call' and 'dword ptr [' in insn.op_str:
            print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")

# 7. Also check the existing session timeout patches
print("\n=== Verify session timeout patches ===")
for name, va, expected in [
    ("session_timeout_timer_1", 0x10645cd1, b"\x74\x11"),
    ("session_timeout_timer_2", 0x10645d68, b"\x74\x5c"),
]:
    foff = va_to_foff(va)
    actual = b[foff:foff+len(expected)]
    match = "OK" if actual == expected else "MISMATCH"
    print(f"  {name}: VA=0x{va:x} expected={expected.hex()} actual={actual.hex()} [{match}]")
