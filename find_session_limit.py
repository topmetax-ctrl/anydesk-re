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

# 1. Find all occurrences of "session.timeout" and "session_timeout" strings
# and get their full string addresses
print("=== String locations ===")
for pattern in [b'session.timeout\x00', b'session_timeout\x00', 
                b'session_time\x00', b'session_timeout_countdown\x00']:
    pos = 0
    while True:
        pos = b.find(pattern, pos)
        if pos < 0:
            break
        va = foff_to_va(pos)
        print(f"  0x{va:08x}: '{pattern[:-1].decode()}'")
        pos += 1

# 2. AnyDesk uses a hash-based string lookup system.
# The string keys are registered in a table. Let me find the string table entries.
# Look for the pattern: push <string_addr>; call <register_func>
# near the string locations

# 3. Instead, let's look at the countdown code we already patched
# The countdown at 0x10626bbb is in a switch statement
# Let's look at the full function to understand the session timeout mechanism
print("\n=== Countdown function context ===")
md = Cs(CS_ARCH_X86, CS_MODE_32)

# Find function start for 0x10626bbb
target_va = 0x10626bbb
target_foff = va_to_foff(target_va)
for offset in range(1, 2048):
    check = target_foff - offset
    if b[check:check+3] == b'\x55\x8b\xec':
        func_start = target_va - offset
        print(f"  Function start: 0x{func_start:x}")
        # Disassemble from function start
        chunk = b[check:check + 2000]
        lines = []
        for insn in md.disasm(chunk, func_start):
            lines.append("  0x%x: %-30s %s %s" % (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
            if insn.mnemonic in ('ret', 'retn') and insn.address > target_va + 100:
                break
            if insn.address > func_start + 1800:
                lines.append("  ... (truncated)")
                break
        with open('/tmp/countdown_func.txt', 'w') as f:
            f.write('\n'.join(lines))
        print(f"  Written {len(lines)} lines to /tmp/countdown_func.txt")
        break

# 4. Search for "session" related config keys used in code
# Look for push of string addresses that contain "session" in .rdata
print("\n=== Searching for 'session' config key references in .text ===")
# Find all "session" strings in .rdata first
rdata_start = sections[1][4] if len(sections) > 1 else 0
rdata_end = rdata_start + sections[1][3] if len(sections) > 1 else 0

session_strings = []
pos = rdata_start
while pos < rdata_end - 7:
    pos = b.find(b'session', pos, rdata_end)
    if pos < 0:
        break
    # Get full string
    end = b.find(b'\x00', pos, pos + 100)
    if end > 0:
        full = b[pos:end].decode('latin1', 'replace')
        if len(full) < 60 and ('session' in full.lower()):
            va = foff_to_va(pos)
            session_strings.append((va, full))
    pos += 1

print(f"  Found {len(session_strings)} session strings in .rdata")
# Now find which ones are referenced in .text
for str_va, str_name in session_strings:
    str_bytes = struct.pack('<I', str_va)
    pos = text_start
    count = 0
    while pos < text_end - 4:
        pos = b.find(str_bytes, pos, text_end)
        if pos < 0:
            break
        count += 1
        pos += 1
    if count > 0:
        print(f"  0x{str_va:08x}: '{str_name}' -> {count} refs in .text")
