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

# 1. Show banner function from 0x10840820 to 0x10841190 (the part we're skipping)
print("=== Banner function 0x10840820-0x10841190 (skipped code) ===")
foff = va_to_foff(0x10840820)
chunk = b[foff:foff + 0x970]  # up to epilogue
count = 0
for insn in md.disasm(chunk, 0x10840820):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    count += 1
    if insn.mnemonic in ('ret', 'retn') and insn.address >= 0x10841180:
        break
    if count > 250:
        print("  ... (truncated)")
        break

# 2. Check the three conditional jump bytes for alternative patches
print("\n=== Conditional jumps in banner function ===")
for va, desc in [(0x1084059e, "block1 je"), (0x10840680, "block2 je"), (0x10840768, "block3 je")]:
    foff = va_to_foff(va)
    raw = b[foff:foff+6]
    print(f"  0x{va:x}: {raw.hex()} - {desc}")

# 3. Check what's between block 3 end (0x10840839) and epilogue (0x10841180)
# Is there initialization code that we're skipping?
print("\n=== Code after block 3 (0x10840839-0x10841180) ===")
foff = va_to_foff(0x10840839)
chunk = b[foff:foff + 0x947]
count = 0
for insn in md.disasm(chunk, 0x10840839):
    # Highlight calls and important instructions
    marker = ""
    if insn.mnemonic == 'call':
        marker = " *** CALL ***"
    elif insn.mnemonic in ('je', 'jne', 'jmp', 'jb', 'ja', 'jle', 'jge', 'jbe', 'jae'):
        marker = " <jump>"
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
    count += 1
    if insn.mnemonic in ('ret', 'retn') and insn.address >= 0x10841180:
        break
    if count > 300:
        print("  ... (truncated)")
        break

# 4. Check what 0x1107fc9c does (last call in function 0x10840320)
print("\n=== Function 0x1107fc9c (called by 0x10840320 before return) ===")
foff = va_to_foff(0x1107fc9c)
print(f"  Raw: {b[foff:foff+20].hex()}")
for insn in md.disasm(b[foff:foff+40], 0x1107fc9c):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x1107fcc0:
        break

# 5. Check what 0x1107ed66 and 0x1107eb5d do
print("\n=== Function 0x1107ed66 ===")
foff = va_to_foff(0x1107ed66)
for insn in md.disasm(b[foff:foff+30], 0x1107ed66):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x1107ed80:
        break

print("\n=== Function 0x1107eb5d ===")
foff = va_to_foff(0x1107eb5d)
for insn in md.disasm(b[foff:foff+30], 0x1107eb5d):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x1107eb80:
        break
