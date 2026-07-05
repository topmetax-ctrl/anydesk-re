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
text_va_start = imgbase + sections[0][2]

# Search for direct calls to 0x106c35b0
# call rel32: e8 XX XX XX XX where VA_of_next_instr + rel32 = 0x106c35b0
target_va = 0x106c35b0
print("=== Searching for direct calls to 0x%x ===" % target_va)

callers = []
for i in range(text_start, text_end - 5):
    if b[i] == 0xe8:
        rel32 = struct.unpack_from('<i', b, i + 1)[0]
        call_va = foff_to_va(i)
        next_va = call_va + 5
        dest_va = next_va + rel32
        if dest_va == target_va:
            callers.append(call_va)
            print(f"  Call at VA 0x{call_va:x} (foff 0x{i:x})")

# Also search for references to vtable 0x1195a328
vtable_va = 0x1195a328
print(f"\n=== Searching for references to vtable 0x{vtable_va:x} ===")
vtable_bytes = struct.pack('<I', vtable_va)
pos = text_start
while pos < text_end - 4:
    pos = b.find(vtable_bytes, pos, text_end)
    if pos < 0:
        break
    va = foff_to_va(pos)
    print(f"  Ref at VA 0x{va:x} (foff 0x{pos:x})")
    # Disassemble around this reference
    ctx_start = max(text_start, pos - 32)
    ctx_va = foff_to_va(ctx_start)
    chunk = b[ctx_start:pos + 16]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    print(f"  Context:")
    for insn in md.disasm(chunk, ctx_va):
        marker = " <---" if insn.address <= foff_to_va(pos) < insn.address + insn.size else ""
        print(f"    0x{insn.address:x}: {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}{marker}")
    pos += 1

# Now disassemble around each caller to find conditions
if callers:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for caller_va in callers:
        print(f"\n=== Context around call at 0x{caller_va:x} ===")
        ctx_start_va = caller_va - 80
        ctx_start_foff = va_to_foff(ctx_start_va)
        chunk = b[ctx_start_foff:ctx_start_foff + 120]
        for insn in md.disasm(chunk, ctx_start_va):
            marker = " <--- CALL" if insn.address == caller_va else ""
            print(f"  0x{insn.address:x}: {insn.bytes.hex():<30} {insn.mnemonic} {insn.op_str}{marker}")
