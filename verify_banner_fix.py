import struct, lzma, time, os
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

# 1. Verify calling convention of 0x10d83764
# Look for ret instruction at end of function
func_va = 0x10d83764
func_foff = va_to_foff(func_va)

# Disassemble more of the function to find the ret
md = Cs(CS_ARCH_X86, CS_MODE_32)
# Try from a known good instruction boundary
# We know 0x10d83773 has valid code (mov dword ptr [ebp-0x28], 3)
# Let's disassemble from there and look for ret
chunk = b[va_to_foff(0x10d83773):va_to_foff(0x10d83773) + 2000]
print("=== Disassembling 0x10d83764 region (from 0x10d83773) ===")
ret_found = False
for insn in md.disasm(chunk, 0x10d83773):
    if insn.mnemonic in ('ret', 'retn'):
        print("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
        ret_found = True
        break
    if insn.address > 0x10d83773 + 500:
        break

if not ret_found:
    print("  No ret found in first 500 bytes, trying wider search...")
    chunk2 = b[va_to_foff(0x10d83773):va_to_foff(0x10d83773) + 4000]
    for insn in md.disasm(chunk2, 0x10d83773):
        if insn.mnemonic in ('ret', 'retn'):
            print("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
            break

# 2. Also check: is there an 'add esp, X' after the call site?
# If yes, it's cdecl. If no, it's stdcall/thiscall.
print("\n=== Code after call site (0x106c3774) ===")
after_foff = va_to_foff(0x106c3774)
after_chunk = b[after_foff:after_foff + 100]
for insn in md.disasm(after_chunk, 0x106c3774):
    print("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
    if insn.address > 0x106c3790:
        break

# 3. Verify the new patch bytes
print("\n=== New banner patch ===")
patch_va = 0x106c376f
patch_foff = va_to_foff(patch_va)
orig = b[patch_foff:patch_foff+5]
new_patch = b"\x83\xc4\x14\x90\x90"
print(f"  VA: 0x{patch_va:x}")
print(f"  Original: {orig.hex()} (call 0x10d83764)")
print(f"  New:      {new_patch.hex()} (add esp, 0x14; nop; nop)")

# Verify disassembly of new patch
for insn in md.disasm(new_patch, patch_va):
    print(f"    0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
