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

# Key string addresses to find references for
target_strings = {
    0x11986fb0: 'session_timeout_countdown',
    0x11986fdc: 'session_timeout',
    0x1194570f: 'session.timeout_soon.str',
    0x11302a85: 'session.timeout',
    0x11301fe8: 'session_time',
    0x11947f75: 'session_time',
}

md = Cs(CS_ARCH_X86, CS_MODE_32)

for str_va, str_name in target_strings.items():
    str_bytes = struct.pack('<I', str_va)
    print(f"\n=== References to 0x{str_va:x} ('{str_name}') ===")
    
    pos = text_start
    refs = []
    while pos < text_end - 4:
        pos = b.find(str_bytes, pos, text_end)
        if pos < 0:
            break
        ref_va = foff_to_va(pos)
        refs.append(ref_va)
        pos += 1
    
    print(f"  Found {len(refs)} references")
    for ref_va in refs[:10]:  # Limit to first 10
        # Disassemble around the reference
        ctx_start_foff = va_to_foff(ref_va - 30)
        ctx_start_va = ref_va - 30
        chunk = b[ctx_start_foff:ctx_start_foff + 60]
        print(f"\n  Ref at 0x{ref_va:x}:")
        for insn in md.disasm(chunk, ctx_start_va):
            marker = " <---" if insn.address <= ref_va < insn.address + insn.size else ""
            print(f"    0x{insn.address:x}: {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}{marker}")
            if insn.address > ref_va + 10:
                break
