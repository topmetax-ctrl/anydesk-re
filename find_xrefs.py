import struct

b = open("/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_inner.exe","rb").read()
e = struct.unpack_from('<I', b, 0x3C)[0]
coff = e + 4
nsec = struct.unpack_from('<H', b, coff+2)[0]
optsz = struct.unpack_from('<H', b, coff+16)[0]
opt = coff + 20
imgbase = struct.unpack_from('<I', b, opt+28)[0]
sec_off = opt + optsz
sections = []
for i in range(nsec):
    s = sec_off + i*40
    nm = b[s:s+8].rstrip(b'\x00').decode('latin1','replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', b, s+8)
    sections.append((nm, vs, va, rs, rp))

def file_to_rva(foff):
    for nm, vs, va, rs, rp in sections:
        if rp <= foff < rp + rs:
            return va + (foff - rp)
    return None

def rva_to_file(rva):
    for nm, vs, va, rs, rp in sections:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

# Key strings and their file offsets
keys = {
    "ad.banner.disconnect_countdown": b"ad.banner.disconnect_countdown",
    "ad.banner.free":                 b"ad.banner.free\x00",
    "ad.banner.free.default":         b"ad.banner.free.default",
    "ad.dlg.netinfo.step.waiting":    b"ad.dlg.netinfo.step.waiting",
    "ad.banner.expired":              b"ad.banner.expired",
    "ad.banner.expires":              b"ad.banner.expires",
}

print("=== String key locations ===")
key_locations = {}
for name, kb in keys.items():
    pos = 0
    locations = []
    while True:
        pos = b.find(kb, pos)
        if pos < 0:
            break
        rva = file_to_rva(pos)
        va = imgbase + rva if rva else 0
        locations.append((pos, rva, va))
        pos += 1
    key_locations[name] = locations
    print(f"  {name}: {len(locations)} occurrences")
    for foff, rva, va in locations[:5]:
        print(f"    foff=0x{foff:x} rva=0x{rva:x} va=0x{va:x}")

# Search for references: try both VA and RVA as 4-byte LE
print("\n=== Searching for VA and RVA references ===")
for name, locs in key_locations.items():
    for foff, rva, va in locs:
        va_bytes = struct.pack('<I', va)
        rva_bytes = struct.pack('<I', rva)
        va_refs = []
        rva_refs = []
        pos = 0
        while True:
            pos = b.find(va_bytes, pos)
            if pos < 0:
                break
            ref_rva = file_to_rva(pos)
            if ref_rva is not None and ref_rva < 0x010af000:  # in .text
                va_refs.append((pos, ref_rva))
            pos += 1
        pos = 0
        while True:
            pos = b.find(rva_bytes, pos)
            if pos < 0:
                break
            ref_rva = file_to_rva(pos)
            if ref_rva is not None and ref_rva < 0x010af000:  # in .text
                rva_refs.append((pos, ref_rva))
            pos += 1
        if va_refs or rva_refs:
            print(f"  {name} @0x{foff:x}: VA_refs={len(va_refs)} RVA_refs={len(rva_refs)}")
            for foff_ref, rva_ref in (va_refs + rva_refs)[:5]:
                print(f"    ref at foff=0x{foff_ref:x} rva=0x{rva_ref:x}")

# Also search for string key as part of a pointer table in .rdata/.data
# Try searching for offsets relative to section start
print("\n=== Searching for string table pointers ===")
# Maybe the strings are referenced by a table of offsets relative to the locale data block
# Let's find the locale data block boundaries
# The English strings seem to be around 0x135e000-0x1380000
# Let's look for a table of pointers to strings in that range

# Try: search for any 4-byte value that equals the file offset of a key string
for name, locs in key_locations.items():
    for foff, rva, va in locs[:2]:
        foff_bytes = struct.pack('<I', foff)
        pos = 0
        refs = []
        while True:
            pos = b.find(foff_bytes, pos)
            if pos < 0:
                break
            ref_rva = file_to_rva(pos)
            if ref_rva is not None:
                refs.append((pos, ref_rva))
            pos += 1
        if refs:
            print(f"  {name} foff=0x{foff:x}: {len(refs)} file-offset refs")
            for foff_ref, rva_ref in refs[:5]:
                print(f"    ref at foff=0x{foff_ref:x} rva=0x{rva_ref:x}")
