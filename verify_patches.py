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

def rva_to_file(rva):
    for nm, vs, va, rs, rp in sections:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

def va_to_file(va):
    return rva_to_file(va - imgbase)

# Verify exact bytes at each patch point
patches = [
    # 1. Countdown: at 0x10626bbb, sub eax,0 -> xor eax,eax; nop
    #    This makes the license switch always take case_0 (no countdown)
    (0x10626bbb, "countdown_switch", b"\x83\xe8\x00", b"\x33\xc0\x90"),

    # 2. Banner constructor: NOP the UI add call at 0x106c376f
    #    call 0x10d83764 -> 5x NOP
    (0x106c376f, "banner_ui_add", b"\xe8\xf0\xff\x6b\x00", b"\x90\x90\x90\x90\x90"),

    # 3. Banner formatter: make it return immediately at 0x1084e520
    #    push ebp; mov ebp,esp -> xor eax,eax; ret 8
    (0x1084e520, "banner_formatter_ret", b"\x55\x8b\xec", b"\x33\xc0\xc2\x08\x00"),
]

print("=== Verifying patch points ===")
for va, name, expected, patch in patches:
    foff = va_to_file(va)
    actual = b[foff:foff+len(expected)]
    match = actual == expected
    print(f"  {name} at VA=0x{va:x} foff=0x{foff:x}")
    print(f"    expected: {expected.hex(' ')}")
    print(f"    actual:   {actual.hex(' ')}")
    print(f"    match: {match}")
    if not match:
        print(f"    *** MISMATCH! ***")
    print(f"    patch:    {patch.hex(' ')} ({len(patch)} bytes)")

# Also check: what's the ret convention for the banner formatter?
# Look at the end of the function to find ret bytes
print("\n=== Banner formatter return convention ===")
# The function at 0x1084e520 - find its ret
# It jumps to 0x1109c2aa and 0x1109c1d5 - let's check those
for target_va in [0x1109c2aa, 0x1109c1d5]:
    foff = va_to_file(target_va)
    if foff:
        chunk = b[foff:foff+30]
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        print(f"  At 0x{target_va:x}:")
        for insn in md.disasm(chunk, target_va):
            print(f"    0x{insn.address:08x}: {insn.bytes.hex():<20s} {insn.mnemonic} {insn.op_str}")
            if 'ret' in insn.mnemonic:
                break

# Check what calls the banner constructor - search for E8 rel32 to 0x106c35b0
print("\n=== Direct calls to banner constructor 0x106c35b0 ===")
text_rp = sections[0][4]
text_rs = sections[0][3]
text_va = imgbase + sections[0][2]
target = 0x106c35b0
for i in range(text_rs - 5):
    if b[text_rp + i] == 0xE8:
        rel = struct.unpack_from('<i', b, text_rp + i + 1)[0]
        call_va = text_va + i
        dest = call_va + 5 + rel
        if dest == target:
            print(f"  call at 0x{call_va:08x} (foff=0x{text_rp+i:x})")

# Check what calls the banner formatter 0x1084e520
print("\n=== Direct calls to banner formatter 0x1084e520 ===")
target = 0x1084e520
for i in range(text_rs - 5):
    if b[text_rp + i] == 0xE8:
        rel = struct.unpack_from('<i', b, text_rp + i + 1)[0]
        call_va = text_va + i
        dest = call_va + 5 + rel
        if dest == target:
            print(f"  call at 0x{call_va:08x} (foff=0x{text_rp+i:x})")

# Check what calls the countdown handler 0x10626b70
print("\n=== Direct calls to countdown handler 0x10626b70 ===")
target = 0x10626b70
for i in range(text_rs - 5):
    if b[text_rp + i] == 0xE8:
        rel = struct.unpack_from('<i', b, text_rp + i + 1)[0]
        call_va = text_va + i
        dest = call_va + 5 + rel
        if dest == target:
            print(f"  call at 0x{call_va:08x} (foff=0x{text_rp+i:x})")
