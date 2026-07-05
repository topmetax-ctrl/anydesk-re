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

# 1. Dump vtable at 0x1195a328 (in .rdata)
vtable_va = 0x1195a328
vtable_foff = va_to_foff(vtable_va)
print(f"=== Vtable at 0x{vtable_va:x} (foff 0x{vtable_foff:x}) ===")
for i in range(32):
    ptr = struct.unpack_from('<I', b, vtable_foff + i*4)[0]
    print(f"  [{i*4:#06x}] -> 0x{ptr:08x}")

# 2. Look at the first reference site (0x106c2450) - find function start
ref1_va = 0x106c2450
ref1_foff = va_to_foff(ref1_va)
# Search backwards for prologue
for offset in range(1, 512):
    check = ref1_foff - offset
    if b[check] == 0x55 and b[check+1] == 0x8b and b[check+2] == 0xec:
        func_start = ref1_va - offset
        print(f"\n=== Function at 0x{func_start:x} (first vtable ref) ===")
        # Disassemble 200 bytes
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        chunk = b[check:check+300]
        for insn in md.disasm(chunk, func_start):
            marker = ""
            if insn.address == ref1_va:
                marker = " <--- vtable assign"
            elif insn.address == ref1_va + 6:
                marker = " <--- vtable+8"
            print(f"  0x{insn.address:x}: {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}{marker}")
            if insn.mnemonic == 'ret':
                break
        break

# 3. Search for calls to this function
print(f"\n=== Searching for calls to 0x{func_start:x} ===")
text_start = sections[0][4]
text_end = text_start + sections[0][3]
callers = []
for i in range(text_start, text_end - 5):
    if b[i] == 0xe8:
        rel32 = struct.unpack_from('<i', b, i + 1)[0]
        call_va = foff_to_va(i)
        dest = call_va + 5 + rel32
        if dest == func_start:
            callers.append(call_va)

print(f"Found {len(callers)} callers")
for c in callers:
    print(f"  Call at 0x{c:x}")
