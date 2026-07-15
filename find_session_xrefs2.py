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

# The banner constructor used these string IDs (pushed as args):
# 0x1195a180, 0x1195a164, 0x1195a140, 0x1195a210, 0x1195a1f8, 0x1195a098
# These are likely localization string keys. Let me read the full strings.
print("=== String IDs from banner constructor ===")
string_ids = [0x1195a098, 0x1195a140, 0x1195a164, 0x1195a180, 0x1195a1f8, 0x1195a210]
for sid in string_ids:
    sid_foff = va_to_foff(sid)
    # Read backwards to find the start of the string key
    start = sid_foff
    while start > 0 and b[start-1] != 0:
        start -= 1
    end = b.find(b'\x00', sid_foff, sid_foff + 200)
    full = b[start:end].decode('latin1', 'replace')
    va = foff_to_va(start)
    print(f"  0x{va:08x}: '{full}'")

# Now search for the retry_limit and closed strings
print("\n=== Searching for retry_limit strings ===")
search = b'retry_limit'
pos = 0
while True:
    pos = b.find(search, pos)
    if pos < 0:
        break
    start = pos
    while start > 0 and b[start-1] != 0:
        start -= 1
    end = b.find(b'\x00', pos, pos + 200)
    full = b[start:end].decode('latin1', 'replace')
    va = foff_to_va(start)
    print(f"  0x{va:08x}: '{full}'")
    pos += 1

print("\n=== Searching for 'closed.' strings ===")
search = b'closed.'
pos = 0
while True:
    pos = b.find(search, pos)
    if pos < 0:
        break
    start = pos
    while start > 0 and b[start-1] != 0:
        start -= 1
    end = b.find(b'\x00', pos, pos + 200)
    full = b[start:end].decode('latin1', 'replace')
    va = foff_to_va(start)
    if len(full) < 100:
        print(f"  0x{va:08x}: '{full}'")
    pos += 1

# Search for 'dlg.closed' specifically
print("\n=== Searching for 'dlg.closed' strings ===")
search = b'dlg.closed'
pos = 0
while True:
    pos = b.find(search, pos)
    if pos < 0:
        break
    start = pos
    while start > 0 and b[start-1] != 0:
        start -= 1
    end = b.find(b'\x00', pos, pos + 200)
    full = b[start:end].decode('latin1', 'replace')
    va = foff_to_va(start)
    print(f"  0x{va:08x}: '{full}'")
    pos += 1

# Now find xrefs to these string addresses
print("\n=== Searching for xrefs to key strings ===")
# The string keys are used as push args. Let me search for push of these addresses
key_strings = []
search_terms = [b'dlg.closed.retry_limit_reached', b'dlg.closed.socket_closed', 
                b'dlg.closed.socket_timeout', b'session.timeout']
for term in search_terms:
    pos = 0
    while True:
        pos = b.find(term, pos)
        if pos < 0:
            break
        start = pos
        while start > 0 and b[start-1] != 0:
            start -= 1
        end = b.find(b'\x00', pos, pos + 200)
        full = b[start:end].decode('latin1', 'replace')
        va = foff_to_va(start)
        key_strings.append((va, full))
        pos += 1

for str_va, str_name in key_strings:
    str_bytes = struct.pack('<I', str_va)
    pos = text_start
    refs = []
    while pos < text_end - 4:
        pos = b.find(str_bytes, pos, text_end)
        if pos < 0:
            break
        refs.append(foff_to_va(pos))
        pos += 1
    print(f"\n  '{str_name}' at 0x{str_va:x}: {len(refs)} refs")
    for r in refs[:5]:
        print(f"    ref at 0x{r:x}")
