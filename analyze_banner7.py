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

# 1. Search for SetTimer calls within banner function range
print("=== SetTimer calls in banner function 0x10840500-0x10841190 ===")
settimer_pattern = b'\xff\x15\x18\xf7\x0a\x11'
foff_start = va_to_foff(0x10840500)
foff_end = va_to_foff(0x10841190)
pos = foff_start
while pos < foff_end - 6:
    pos = b.find(settimer_pattern, pos, foff_end)
    if pos < 0:
        break
    call_va = foff_to_va(pos)
    print(f"  SetTimer call at 0x{call_va:x}")
    pos += 1

# Also search for any indirect call in the banner function
print("\n=== All indirect calls in banner function ===")
chunk = b[foff_start:foff_end]
for insn in md.disasm(chunk, 0x10840500):
    if insn.mnemonic == 'call' and ('dword ptr [' in insn.op_str or '0x110' in insn.op_str):
        print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    if insn.address >= 0x10841190:
        break

# 2. Show the rest of the banner function (0x10840820-0x10841190)
print("\n=== Banner function 0x10840820-0x10841190 ===")
foff = va_to_foff(0x10840820)
chunk = b[foff:foff + 0x970]  # up to 0x10841190
count = 0
for insn in md.disasm(chunk, 0x10840820):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    count += 1
    if insn.mnemonic in ('ret', 'retn') and insn.address >= 0x10841180:
        break
    if count > 200:
        print("  ... (truncated at 200 instructions)")
        break

# 3. Check the 1-second timer call site at 0x105b55af - find its function
print("\n=== Function containing 0x105b55af (1s timer) ===")
foff = va_to_foff(0x105b55af)
for offset in range(1, 8192):
    check = foff - offset
    if b[check:check+3] == b'\x55\x8b\xec':
        func_start = 0x105b55af - offset
        print(f"  Function start: 0x{func_start:x}")
        # Show 10 instructions before the SetTimer call
        ctx_foff = va_to_foff(0x105b5580)
        chunk = b[ctx_foff:ctx_foff + 60]
        for insn in md.disasm(chunk, 0x105b5580):
            marker = " <--- SetTimer" if insn.address == 0x105b55af else ""
            print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
            if insn.address > 0x105b55c0:
                break
        # Find callers of this function
        target_va = func_start
        callers = []
        for i in range(text_start, text_end - 5):
            if b[i] == 0xe8:
                rel32 = struct.unpack_from('<i', b, i + 1)[0]
                call_va = foff_to_va(i)
                dest = call_va + 5 + rel32
                if dest == target_va:
                    callers.append(call_va)
        print(f"  Callers: {len(callers)}")
        for c in callers[:5]:
            print(f"    0x{c:x}")
        break
