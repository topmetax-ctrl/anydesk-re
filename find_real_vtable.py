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

# 1. Check what's at 0x11937308 (first value stored in [ebx])
vtable_va = 0x11937308
vtable_foff = va_to_foff(vtable_va)
print("=== Possible vtable at 0x%x ===" % vtable_va)
for i in range(20):
    ptr = struct.unpack_from('<I', b, vtable_foff + i*4)[0]
    # Check if it looks like a code pointer (in .text range)
    va_start = imgbase + sections[0][2]
    va_end = va_start + sections[0][1]
    is_code = va_start <= ptr < va_end
    print("  [+0x%02x] 0x%08x %s" % (i*4, ptr, "(code)" if is_code else ""))

# 2. Search for calls to 0x106c35b0 (banner constructor) - also check indirect via vtable
# First, find which vtable slot contains 0x106c35b0
constructor_va = 0x106c35b0
print("\n=== Searching for 0x%x in .rdata (vtable slot) ===" % constructor_va)
rdata_start = sections[1][4]
rdata_end = rdata_start + sections[1][3]
ctor_bytes = struct.pack('<I', constructor_va)
pos = rdata_start
while pos < rdata_end:
    pos = b.find(ctor_bytes, pos, rdata_end)
    if pos < 0:
        break
    va = foff_to_va(pos)
    # Check surrounding entries
    print("  Found at VA 0x%08x" % va)
    # Check if this is part of a vtable (surrounding entries should be code ptrs)
    for offset in [-4, 0, 4, 8]:
        ptr = struct.unpack_from('<I', b, pos + offset)[0]
        is_code = (imgbase + sections[0][2]) <= ptr < (imgbase + sections[0][2] + sections[0][1])
        print("    [%+d] 0x%08x %s" % (offset, ptr, "(code)" if is_code else ""))
    pos += 1

# 3. Search for the real vtable 0x11937308 references in .text
print("\n=== Searching for refs to vtable 0x11937308 in .text ===")
vtable_ref = struct.pack('<I', vtable_va)
pos = text_start
refs = []
while pos < text_end - 4:
    pos = b.find(vtable_ref, pos, text_end)
    if pos < 0:
        break
    va = foff_to_va(pos)
    refs.append(va)
    pos += 1

print("Found %d references" % len(refs))
for ref_va in refs:
    print("\n  Ref at 0x%x:" % ref_va)
    # Disassemble around this reference
    ctx_start = max(text_start, va_to_foff(ref_va - 40))
    ctx_va = foff_to_va(ctx_start)
    chunk = b[ctx_start:va_to_foff(ref_va) + 20]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for insn in md.disasm(chunk, ctx_va):
        marker = " <---" if insn.address <= ref_va < insn.address + insn.size else ""
        print("    0x%x: %-30s %s %s%s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str, marker))
