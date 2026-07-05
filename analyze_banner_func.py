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

# Verify call target
call_va = 0x106c376f
call_foff = va_to_foff(call_va)
call_bytes = b[call_foff:call_foff+5]
print(f"Call at VA {hex(call_va)}, foff {hex(call_foff)}: {call_bytes.hex()}")
rel32 = struct.unpack_from('<i', b, call_foff+1)[0]
target_va = call_va + 5 + rel32
print(f"rel32 = {hex(rel32)}, target VA = {hex(target_va)}")

# Check bytes at target
target_foff = va_to_foff(target_va)
target_bytes = b[target_foff:target_foff+32]
print(f"\nTarget VA {hex(target_va)}, foff {hex(target_foff)}")
print(f"Raw bytes: {target_bytes.hex()}")

# Try disassembling from target
md = Cs(CS_ARCH_X86, CS_MODE_32)
print(f"\nDisassembly from target:")
for i in md.disasm(target_bytes, target_va):
    print(f"  0x{i.address:x}: {i.bytes.hex():<30} {i.mnemonic} {i.op_str}")

# Also check: maybe the function starts a few bytes before
print(f"\nBytes before target (16 bytes):")
before = b[target_foff-16:target_foff]
print(f"  {before.hex()}")
for i in md.disasm(before, target_va - 16):
    print(f"  0x{i.address:x}: {i.bytes.hex():<30} {i.mnemonic} {i.op_str}")

# Look for push ebp; mov ebp, esp pattern before target
for offset in range(1, 64):
    check_foff = target_foff - offset
    if b[check_foff] == 0x55 and b[check_foff+1] == 0x8b and b[check_foff+2] == 0xec:
        func_start_va = target_va - offset
        print(f"\nFound prologue (push ebp; mov ebp,esp) at VA {hex(func_start_va)} (offset -{offset})")
        # Disassemble from there
        prologue_bytes = b[check_foff:check_foff+200]
        for i in md.disasm(prologue_bytes, func_start_va):
            print(f"  0x{i.address:x}: {i.bytes.hex():<30} {i.mnemonic} {i.op_str}")
        break
