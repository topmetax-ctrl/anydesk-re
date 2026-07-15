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

# 1. Analyze 0x11a67483 - the license check function
print("=== Function 0x11a67483 ===")
func_foff = va_to_foff(0x11a67483)
chunk = b[func_foff:func_foff + 500]
lines = []
for insn in md.disasm(chunk, 0x11a67483):
    lines.append("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
    if insn.mnemonic in ('ret', 'retn') and insn.address > 0x11a67490:
        break
    if insn.address > 0x11a67600:
        lines.append("  ... (truncated)")
        break
with open('/tmp/license_func.txt', 'w') as f:
    f.write('\n'.join(lines))
print(f"  Written {len(lines)} lines to /tmp/license_func.txt")

# 2. Find the vtable containing 0x10626b70 (countdown function)
print("\n=== Vtable search for 0x10626b70 ===")
ctor_bytes = struct.pack('<I', 0x10626b70)
# Search in all sections
pos = 0
while True:
    pos = b.find(ctor_bytes, pos)
    if pos < 0:
        break
    va = foff_to_va(pos)
    for sec in sections:
        if sec[4] <= pos < sec[4] + sec[3]:
            print(f"  Found at 0x{va:x} in {sec[0]}")
            if sec[0] == '.rdata':
                # Dump vtable context
                for offset in range(-4, 8):
                    ptr_pos = pos + offset * 4
                    ptr = struct.unpack_from('<I', b, ptr_pos)[0]
                    pva = foff_to_va(ptr_pos)
                    is_code = (imgbase + sections[0][2]) <= ptr < (imgbase + sections[0][2] + sections[0][1])
                    print(f"    [{offset:+d}] 0x{pva:08x} -> 0x{ptr:08x} {'(code)' if is_code else ''}")
            break
    pos += 1

# 3. Search for the session timeout enforcement
# The key insight: the countdown function at 0x10626b70 is called when a session
# timeout is approaching. The actual timeout is likely enforced by a timer.
# Let me search for SetTimer API calls
print("\n=== Searching for SetTimer/KillTimer imports ===")
# Search in import table
for api in [b'SetTimer', b'KillTimer', b'SetWaitableTimer', b'CreateWaitableTimer']:
    pos = 0
    while True:
        pos = b.find(api, pos)
        if pos < 0:
            break
        va = foff_to_va(pos)
        # Read full string
        end = b.find(b'\x00', pos, pos + 50)
        full = b[pos:end].decode('latin1', 'replace')
        print(f"  0x{va:x}: '{full}'")
        pos += 1

# 4. Search for time-related comparisons in the countdown function area
# The countdown function uses [ebx + 0x2e8] and [ebx + 0x2ec] as a 64-bit value
# This is likely the session timeout duration in some unit
# Let me find where these are SET
print("\n=== Searching for mov [reg+0x2e8], reg ===")
# Pattern: 89 XX e8 02 00 00 or 89 XX e9 02 00 00
for offset_byte in [0xe8, 0xe9]:
    pattern = bytes([0x89]) + bytes([offset_byte]) + b'\xe8\x02\x00\x00'
    # Also try 8b (mov reg, [reg+0x2e8])
    pos = text_start
    while pos < text_end - 6:
        pos = b.find(pattern, pos, text_end)
        if pos < 0:
            break
        ref_va = foff_to_va(pos)
        # Disassemble
        ctx_foff = va_to_foff(ref_va - 10)
        chunk = b[ctx_foff:ctx_foff + 30]
        for insn in md.disasm(chunk, ref_va - 10):
            marker = " <---" if insn.address == ref_va else ""
            print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
            if insn.address > ref_va + 10:
                break
        print()
        pos += 1

# 5. Also search for 0x2ec offset
print("\n=== Searching for access to [reg+0x2ec] ===")
pattern2 = b'\xec\x02\x00\x00'
pos = text_start
count = 0
while pos < text_end - 4:
    pos = b.find(pattern2, pos, text_end)
    if pos < 0:
        break
    if pos >= 2 and b[pos-2] in (0x89, 0x8b, 0xc7):
        ref_va = foff_to_va(pos - 2)
        count += 1
        if count <= 5:
            ctx_foff = va_to_foff(ref_va - 10)
            chunk = b[ctx_foff:ctx_foff + 30]
            for insn in md.disasm(chunk, ref_va - 10):
                marker = " <---" if insn.address == ref_va else ""
                print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
                if insn.address > ref_va + 10:
                    break
            print()
    pos += 1
print(f"  Total: {count} refs")
