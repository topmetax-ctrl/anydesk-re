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

# Disassemble the called function 0x10d83764 - first 200 bytes
func_va = 0x10d83764
func_foff = va_to_foff(func_va)
chunk = b[func_foff:func_foff + 300]

md = Cs(CS_ARCH_X86, CS_MODE_32)
lines = []
for i in md.disasm(chunk, func_va):
    lines.append("  0x%x: %-30s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))

with open('/tmp/banner_func_disasm.txt', 'w') as f:
    f.write('\n'.join(lines))

print("Done, %d lines" % len(lines))
