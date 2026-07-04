"""Verify all new patch points before writing the full patcher."""
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

def r2f(rva):
    for vs, va, rs, rp in sections:
        if va <= rva < va + max(vs, rs): return rp + (rva - va)
    return None

def va2f(va): return r2f(va - imgbase)

md = Cs(CS_ARCH_X86, CS_MODE_32)

patches = [
    # 4. Premium dialog #1: je -> jmp
    (0x10670788, "premium_dialog_1", b"\x74\x58", b"\xEB\x58"),
    # 6. Address book limit: jne -> jmp (6-byte jne -> nop+jmp)
    (0x108c2f4b, "abook_limit", b"\x0f\x85\x6b\x01\x00\x00", b"\x90\xe9\x6b\x01\x00\x00"),
    # 7. Screen recording check #1: jne -> jmp
    (0x105c3f19, "screen_record_1", b"\x0f\x85\xb0\x01\x00\x00", b"\x90\xe9\xb0\x01\x00\x00"),
    # 8. Screen recording check #2: jne -> jmp
    (0x105c3f32, "screen_record_2", b"\x0f\x85\x8a\x00\x00\x00", b"\x90\xe9\x8a\x00\x00\x00"),
    # 9. Session invitation: jne -> jmp (2-byte jne)
    (0x10727b75, "session_invite", b"\x75\x07", b"\xEB\x07"),
]

print("=== Verifying new patch points ===\n")
all_ok = True
for va, name, expected, patch in patches:
    foff = va2f(va)
    actual = b[foff:foff + len(expected)]
    match = actual == expected
    status = "OK" if match else "MISMATCH"
    if not match: all_ok = False
    print(f"  [{status}] {name} at VA=0x{va:x} foff=0x{foff:x}")
    print(f"    expected: {expected.hex(' ')}")
    print(f"    actual:   {actual.hex(' ')}")
    print(f"    patch:    {patch.hex(' ')}")
    # Disassemble to verify context
    chunk = b[max(0,foff-10):foff+len(expected)+10]
    start_va = va - 10
    for insn in md.disasm(chunk, start_va):
        marker = " <--- PATCH" if insn.address == va else ""
        print(f"      0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}{marker}")
    print()

# Also check premium dialog #2 and connection limit more carefully
print("=== Premium dialog #2 context (0x106ea90a area) ===")
foff = va2f(0x106ea900)
chunk = b[foff:foff+80]
for insn in md.disasm(chunk, 0x106ea900):
    print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
    if insn.address > 0x106ea950:
        break

print("\n=== Connection limit context (0x10735f6c area) ===")
foff = va2f(0x10735f60)
chunk = b[foff:foff+60]
for insn in md.disasm(chunk, 0x10735f60):
    print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
    if insn.address > 0x10735fa0:
        break

print(f"\n{'='*50}")
print(f"ALL PATCHES VERIFIED: {all_ok}")
