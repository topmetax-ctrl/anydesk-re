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
md = Cs(CS_ARCH_X86, CS_MODE_32)

# Find all SetTimer call sites and show context with timer interval
settimer_pattern = b'\xff\x15\x18\xf7\x0a\x11'
pos = text_start
call_sites = []
while pos < text_end - 6:
    pos = b.find(settimer_pattern, pos, text_end)
    if pos < 0:
        break
    call_va = foff_to_va(pos)
    call_sites.append(call_va)
    pos += 1

print(f"=== All {len(call_sites)} SetTimer call sites ===")
for c in call_sites:
    # Disassemble 60 bytes before the call to find push instructions
    ctx_foff = va_to_foff(c - 60)
    chunk = b[ctx_foff:ctx_foff + 70]
    lines = []
    for insn in md.disasm(chunk, c - 60):
        if insn.address > c + 6:
            break
        marker = " <--- SetTimer" if insn.address == c else ""
        lines.append(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
    
    # Check if any push instruction has 0x3e8 (1000ms) or 0xf4240 (1000000ms)
    ctx_text = '\n'.join(lines)
    has_3e8 = '0x3e8' in ctx_text
    has_f4240 = '0xf4240' in ctx_text
    has_large = any(f'0x{v:x}' in ctx_text for v in range(0x10000, 0x200000))
    
    if has_3e8 or has_f4240 or has_large:
        label = []
        if has_3e8: label.append("1s-timer")
        if has_f4240: label.append("1000s-timer")
        if has_large: label.append("large-timer")
        print(f"\n*** Call at 0x{c:x} [{', '.join(label)}] ***")
        print(ctx_text)
