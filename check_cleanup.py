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

md = Cs(CS_ARCH_X86, CS_MODE_32)

# 1. Full cleanup sequence after call 0x10d83764
# From 0x106c3774 to function end (look for ret)
print("=== Full cleanup after banner call (0x106c3774 onwards) ===")
start_foff = va_to_foff(0x106c3774)
chunk = b[start_foff:start_foff + 500]
for insn in md.disasm(chunk, 0x106c3774):
    print("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
    if insn.mnemonic in ('ret', 'retn') and insn.address > 0x106c3800:
        break
    if insn.address > 0x106c3900:
        print("  ... (truncated)")
        break

# 2. Check all ret instructions in 0x10d83764 function
print("\n=== All ret instructions in 0x10d83764 ===")
func_foff = va_to_foff(0x10d83773)  # Start from known good boundary
chunk2 = b[func_foff:func_foff + 2000]
for insn in md.disasm(chunk2, 0x10d83773):
    if insn.mnemonic in ('ret', 'retn'):
        print("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
    if insn.address > 0x10d83a00:
        break

# 3. Check if 0x111749d8 (constructor) is thiscall or cdecl
print("\n=== Checking 0x111749d8 return type ===")
ctor_foff = va_to_foff(0x111749d8)
ctor_chunk = b[ctor_foff:ctor_foff + 500]
for insn in md.disasm(ctor_chunk, 0x111749d8):
    if insn.mnemonic in ('ret', 'retn'):
        print("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
        break
    if insn.address > 0x11174b00:
        print("  No ret found in range")
        break
