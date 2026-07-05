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

# Look at wider context: 0x106c3600 to 0x106c37a0
start_va = 0x106c3600
end_va = 0x106c37a0
start_foff = va_to_foff(start_va)
end_foff = va_to_foff(end_va)
chunk = b[start_foff:end_foff]

md = Cs(CS_ARCH_X86, CS_MODE_32)
lines = []
for i in md.disasm(chunk, start_va):
    lines.append("  0x%x: %-30s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))

with open('/tmp/banner_wide_disasm.txt', 'w') as f:
    f.write('\n'.join(lines))

print("Done, %d lines written to /tmp/banner_wide_disasm.txt" % len(lines))
