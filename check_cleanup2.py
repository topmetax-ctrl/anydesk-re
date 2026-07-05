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

# Full cleanup after banner call - write to file
lines = []
start_foff = va_to_foff(0x106c3774)
chunk = b[start_foff:start_foff + 800]
for insn in md.disasm(chunk, 0x106c3774):
    lines.append("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
    if insn.mnemonic in ('ret', 'retn') and insn.address > 0x106c3800:
        break
    if insn.address > 0x106c3a00:
        lines.append("  ... (truncated at 0x106c3a00)")
        break

with open('/tmp/banner_cleanup.txt', 'w') as f:
    f.write('\n'.join(lines))
print(f"Written {len(lines)} lines to /tmp/banner_cleanup.txt")

# Also check: what's at 0x10d83764 - try to find real function entry
# Search backwards for ret/nop/int3 that would mark function boundary
print("\n=== Function boundary search before 0x10d83764 ===")
target_foff = va_to_foff(0x10d83764)
for offset in range(1, 32):
    check_foff = target_foff - offset
    byte = b[check_foff]
    if byte in (0xc3, 0xcc, 0x90):  # ret, int3, nop
        boundary_va = 0x10d83764 - offset
        print(f"  Found boundary byte 0x{byte:02x} at VA 0x{boundary_va:x} (offset -{offset})")
        # The next instruction after this boundary should be the function entry
        next_va = boundary_va + 1
        next_foff = check_foff + 1
        # But we need to check if the instruction at boundary is 1 byte
        if byte == 0xc3:  # ret is 1 byte
            entry_va = next_va
            entry_foff = next_foff
            print(f"  Function entry likely at VA 0x{entry_va:x}")
            # Disassemble from entry
            entry_chunk = b[entry_foff:entry_foff + 300]
            entry_lines = []
            for insn in md.disasm(entry_chunk, entry_va):
                entry_lines.append("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
                if insn.mnemonic in ('ret', 'retn'):
                    break
                if insn.address > entry_va + 400:
                    break
            with open('/tmp/banner_func_entry.txt', 'w') as f:
                f.write('\n'.join(entry_lines))
            print(f"  Written {len(entry_lines)} lines to /tmp/banner_func_entry.txt")
        break
