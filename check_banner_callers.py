import struct, lzma, os
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

# 1. Find ALL callers of 0x10d83764
target_va = 0x10d83764
print("=== All callers of 0x%x ===" % target_va)
callers = []
for i in range(text_start, text_end - 5):
    if b[i] == 0xe8:
        rel32 = struct.unpack_from('<i', b, i + 1)[0]
        call_va = foff_to_va(i)
        dest = call_va + 5 + rel32
        if dest == target_va:
            callers.append(call_va)

print("Found %d callers:" % len(callers))
for c in callers:
    print("  0x%x" % c)

# 2. For each caller, show brief context (what container is used)
md = Cs(CS_ARCH_X86, CS_MODE_32)
for caller_va in callers:
    print("\n  --- Caller at 0x%x ---" % caller_va)
    ctx_start = va_to_foff(caller_va - 20)
    chunk = b[ctx_start:ctx_start + 30]
    for insn in md.disasm(chunk, caller_va - 20):
        if insn.address > caller_va + 5:
            break
        marker = " <--- CALL" if insn.address == caller_va else ""
        print("    0x%x: %-28s %s %s%s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str, marker))

# 3. Verify the patch
patch_va = 0x10d83764
patch_foff = va_to_foff(patch_va)
orig_byte = b[patch_foff]
print("\n=== Patch verification ===")
print("  VA: 0x%x, foff: 0x%x" % (patch_va, patch_foff))
print("  Original byte: 0x%02x" % orig_byte)
print("  Patch byte: 0xC3 (ret)")
