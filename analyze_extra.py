"""
Analyze premium dialog #2 and connection limit to find additional patch points.

Premium dialog #2 at 0x106ea932:
  sub ecx, 0; je 0x106ea941  -> case 0: mov eax, 0x1104
  sub ecx, 1; je 0x106ea946  -> case 1: mov eax, 0x7a0
  default: 0x106ea941: mov eax, 0x7a0
This is a switch on [edi+0x6a8] (some feature flag).
If we patch sub ecx,0 -> xor ecx,ecx, it always takes case_0 (eax=0x1104).
But we need to understand what 0x1104 vs 0x7a0 means.

Connection limit at 0x10735f6c:
  sub eax, 0; je 0x10735f7b  -> case 0: mov eax, 0x98c
  sub eax, 1; je 0x10735f80  -> case 1: mov eax, 0x12f0
  default: 0x10735f74: mov eax, 0x12f0
This is also a switch. eax comes from a previous call.
If we patch sub eax,0 -> xor eax,eax, it always takes case_0 (eax=0x98c).
But 0x98c might be the error path. Need to check what happens with each value.

Let me trace more context for both.
"""
import struct
from capstone import *

b = open("/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_inner.exe","rb").read()
e = struct.unpack_from('<I', b, 0x3C)[0]
coff = e + 4; nsec = struct.unpack_from('<H', b, coff+2)[0]
optsz = struct.unpack_from('<H', b, coff+16)[0]
opt = coff + 20; imgbase = struct.unpack_from('<I', b, opt+28)[0]
sec_off = opt + optsz; sections = []
for i in range(nsec):
    s = sec_off + i*40
    vs, va, rs, rp = struct.unpack_from('<IIII', b, s+8)
    sections.append((vs, va, rs, rp))

def r2f(rva):
    for vs, va, rs, rp in sections:
        if va <= rva < va + max(vs, rs): return rp + (rva - va)
    return None

def va2f(va): return r2f(va - imgbase)
md = Cs(CS_ARCH_X86, CS_MODE_32)

# Premium dialog #2: wider context
print("=== Premium dialog #2: full function context ===")
foff = va2f(0x106ea8f0)
chunk = b[foff:foff+120]
for insn in md.disasm(chunk, 0x106ea8f0):
    print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
    if insn.address > 0x106ea960:
        break

# Connection limit: wider context - find where eax is set before the switch
print("\n=== Connection limit: trace eax source ===")
foff = va2f(0x10735f30)
chunk = b[foff:foff+80]
for insn in md.disasm(chunk, 0x10735f30):
    print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
    if insn.address > 0x10735f80:
        break

# The conn_limit function at 0x10735f30 - find its start
print("\n=== Connection limit function start ===")
for off in range(1, 500):
    foff_check = va2f(0x10735f30 - off)
    if b[foff_check:foff_check+3] == b'\x55\x8b\xec':
        func_va = 0x10735f30 - off
        print(f"  Function start: 0x{func_va:08x}")
        chunk = b[foff_check:foff_check+100]
        for insn in md.disasm(chunk, func_va):
            print(f"    0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
            if insn.address > func_va + 60:
                break
        break

# Session queue limit: find the actual check
print("\n=== Session queue limit context ===")
foff = va2f(0x1081bef0)
chunk = b[foff:foff+80]
for insn in md.disasm(chunk, 0x1081bef0):
    print(f"  0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
    if insn.address > 0x1081bf60:
        break
