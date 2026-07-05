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

# 1. Dump vtable at 0x1195a328
vtable_va = 0x1195a328
vtable_foff = va_to_foff(vtable_va)
print("=== Vtable at 0x%x ===" % vtable_va)
for i in range(20):
    ptr = struct.unpack_from('<I', b, vtable_foff + i*4)[0]
    print("  [+0x%02x] 0x%08x" % (i*4, ptr))

# 2. Check if 0x106c35b0 is in the vtable
constructor_va = 0x106c35b0
for i in range(20):
    ptr = struct.unpack_from('<I', b, vtable_foff + i*4)[0]
    if ptr == constructor_va:
        print("  *** Constructor found at vtable[%+0x%02x] ***" % (i*4))

# 3. Search for banner-related strings in .rdata
rdata_start = sections[1][4]
rdata_end = rdata_start + sections[1][3]
rdata_va_start = imgbase + sections[1][2]

banner_strings = [
    b'banner\x00',
    b'ad.banner\x00',
    b'ad.dlg.banner\x00',
    b'free_license\x00',
    b'ad.dlg.free\x00',
    b'ad.ui.banner\x00',
    b'ad.free\x00',
    b'ad.lic\x00',
    b'ad.dlg.trial\x00',
    b'trial\x00',
    b'free_version\x00',
    b'ad.bar\x00',
    b'ad.strip\x00',
    b'ad.info\x00',
]

print("\n=== Banner-related strings in .rdata ===")
for s in banner_strings:
    pos = rdata_start
    while pos < rdata_end:
        pos = b.find(s, pos, rdata_end)
        if pos < 0:
            break
        va = foff_to_va(pos)
        # Show context
        end = b.find(b'\x00', pos, rdata_end)
        full_str = b[pos:end].decode('latin1', 'replace')
        print("  0x%08x: '%s'" % (va, full_str))
        pos += 1

# 4. Also search for the string keys used in the banner constructor
# The constructor pushes these string IDs: 0x1195a180, 0x1195a164, 0x1195a140, 0x1195a210, 0x1195a1f8, 0x1195a098
print("\n=== String IDs used in banner constructor ===")
string_ids = [0x1195a180, 0x1195a164, 0x1195a140, 0x1195a210, 0x1195a1f8, 0x1195a098]
for sid in string_ids:
    sid_foff = va_to_foff(sid)
    # Read the string at this address
    end = b.find(b'\x00', sid_foff, rdata_end)
    if end > 0 and end - sid_foff < 200:
        s = b[sid_foff:end].decode('latin1', 'replace')
        print("  0x%08x: '%s'" % (sid, s))
    else:
        # Maybe it's a wide string or structured data
        raw = b[sid_foff:sid_foff+32]
        print("  0x%08x: (raw) %s" % (sid, raw.hex()))
