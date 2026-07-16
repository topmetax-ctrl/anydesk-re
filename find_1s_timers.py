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

# Find SetTimer calls with 0x3e8 (1-second) interval
settimer_pattern = b'\xff\x15\x18\xf7\x0a\x11'
pos = text_start
count = 0
while pos < text_end - 6:
    pos = b.find(settimer_pattern, pos, text_end)
    if pos < 0:
        break
    call_va = foff_to_va(pos)
    # Check 30 bytes before for push 0x3e8
    ctx_before = b[pos-30:pos]
    if b'\x68\xe8\x03\x00\x00' in ctx_before:
        count += 1
        print(f"\n=== 1s SetTimer at 0x{call_va:x} ===")
        ctx_foff = va_to_foff(call_va - 30)
        chunk = b[ctx_foff:ctx_foff + 50]
        for insn in md.disasm(chunk, call_va - 30):
            marker = " <--- SetTimer" if insn.address == call_va else ""
            print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
            if insn.address > call_va + 6:
                break
        # Find function start
        foff = va_to_foff(call_va)
        for offset in range(1, 8192):
            check = foff - offset
            if b[check:check+3] == b'\x55\x8b\xec':
                func_start = call_va - offset
                print(f"  Function start: 0x{func_start:x}")
                break
    pos += 1

print(f"\nTotal 1s SetTimer calls: {count}")

# Also check for SetTimer with 0xF4240 (1000s) interval
print("\n=== SetTimer with 0xF4240 interval ===")
pos = text_start
while pos < text_end - 6:
    pos = b.find(settimer_pattern, pos, text_end)
    if pos < 0:
        break
    call_va = foff_to_va(pos)
    ctx_before = b[pos-30:pos]
    if b'\x68\x40\x42\x0f\x00' in ctx_before:
        print(f"  Found at 0x{call_va:x}")
    pos += 1

# Check for SetTimer with interval from memory (push [reg+offset])
# Look for SetTimer calls near session timeout strings
print("\n=== SetTimer calls near session timeout area (0x10645c00-0x10646000) ===")
foff_start = va_to_foff(0x10645c00)
foff_end = va_to_foff(0x10646000)
chunk = b[foff_start:foff_end]
for insn in md.disasm(chunk, 0x10645c00):
    if insn.mnemonic == 'call':
        print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    if insn.address >= 0x10646000:
        break
