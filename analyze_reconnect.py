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

# 1. Look at the function containing sessions.reconnect ref (0x1072f129)
# Find function start
target_va = 0x1072f129
target_foff = va_to_foff(target_va)
for offset in range(1, 2048):
    check = target_foff - offset
    if b[check:check+3] == b'\x55\x8b\xec':
        func_start = target_va - offset
        print(f"Function start: 0x{func_start:x}")
        # Disassemble from function start to target + 100
        end_foff = va_to_foff(target_va + 100)
        chunk = b[check:end_foff]
        lines = []
        for insn in md.disasm(chunk, func_start):
            lines.append("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
        with open('/tmp/reconnect_func.txt', 'w') as f:
            f.write('\n'.join(lines))
        print(f"Written {len(lines)} lines to /tmp/reconnect_func.txt")
        break

# 2. Read the strings at the addresses referenced in this function
# From the output we saw these string addresses being used:
# 0x119678f8, 0x11967a68, 0x119397dc, 0x11967b10, 0x11967b60, 0x11967b24, 0x11967b2c
print("\n=== Strings used in reconnect function ===")
string_addrs = [0x119678f8, 0x11967a68, 0x11967b10, 0x11967b60, 0x11967b24, 0x11967b2c,
                0x119463b8, 0x11946400, 0x1194641c, 0x11946440, 0x11946460, 0x11946494,
                0x119464a4, 0x119464b0, 0x119464c8, 0x119464d0]
for sa in string_addrs:
    sa_foff = va_to_foff(sa)
    start = sa_foff
    while start > 0 and b[start-1] != 0:
        start -= 1
    end = b.find(b'\x00', sa_foff, sa_foff + 200)
    if end > 0:
        full = b[start:end].decode('latin1', 'replace')
        va = foff_to_va = sa - (sa_foff - start)
        print(f"  0x{va:08x}: '{full}'")

# 3. Search for "session_timeout" as a config key - look for hash computations
# AnyDesk likely uses a hash table for config. Let me search for the string
# "session_timeout" being loaded indirectly
print("\n=== Searching for 'session_timeout' in wider context ===")
# Search for the string address 0x11986fdc in entire binary (not just .text)
str_bytes = struct.pack('<I', 0x11986fdc)
pos = 0
count = 0
while count < 20:
    pos = b.find(str_bytes, pos)
    if pos < 0:
        break
    # Determine which section
    for i, sec in enumerate(sections):
        if sec[4] <= pos < sec[4] + sec[3]:
            sec_name = sec[0]
            break
    else:
        sec_name = "?"
    va = pos - sections[0][4] + imgbase + sections[0][2] if pos >= sections[0][4] else pos
    print(f"  Found at foff 0x{pos:x} (section {sec_name})")
    count += 1
    pos += 1

# 4. Search for "session_time" address 0x11947f75
print("\n=== Searching for 'session_time' (0x11947f75) ===")
str_bytes = struct.pack('<I', 0x11947f75)
pos = 0
count = 0
while count < 20:
    pos = b.find(str_bytes, pos)
    if pos < 0:
        break
    for i, sec in enumerate(sections):
        if sec[4] <= pos < sec[4] + sec[3]:
            sec_name = sec[0]
            break
    else:
        sec_name = "?"
    print(f"  Found at foff 0x{pos:x} (section {sec_name})")
    count += 1
    pos += 1
