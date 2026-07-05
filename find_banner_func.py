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

# Search backwards from 0x106c376f for function prologue (55 8b ec = push ebp; mov ebp, esp)
target_va = 0x106c376f
target_foff = va_to_foff(target_va)

# Search up to 2048 bytes back
for offset in range(1, 2048):
    check_foff = target_foff - offset
    if b[check_foff] == 0x55 and b[check_foff+1] == 0x8b and b[check_foff+2] == 0xec:
        func_start_va = target_va - offset
        print(f"Found function prologue at VA 0x{func_start_va:x} (offset -{offset} from banner call)")
        
        # Disassemble from function start to banner call + some cleanup
        end_va = target_va + 0x60
        end_foff = va_to_foff(end_va)
        chunk = b[check_foff:end_foff]
        
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        lines = []
        for i in md.disasm(chunk, func_start_va):
            lines.append("  0x%x: %-30s %s %s" % (i.address, i.bytes.hex(), i.mnemonic, i.op_str))
        
        with open('/tmp/banner_full_func.txt', 'w') as f:
            f.write('\n'.join(lines))
        print(f"Disassembly: {len(lines)} lines -> /tmp/banner_full_func.txt")
        break
else:
    print("No prologue found within 2048 bytes")
    # Try alternate prologues: sub esp, X (83 ec XX or 81 ec XX XX XX XX)
    for offset in range(1, 2048):
        check_foff = target_foff - offset
        if b[check_foff] == 0x83 and b[check_foff+1] == 0xec:
            func_start_va = target_va - offset
            print(f"Found 'sub esp, X' at VA 0x{func_start_va:x} (offset -{offset})")
            break
        if b[check_foff] == 0x81 and b[check_foff+1] == 0xec:
            func_start_va = target_va - offset
            print(f"Found 'sub esp, dword' at VA 0x{func_start_va:x} (offset -{offset})")
            break
