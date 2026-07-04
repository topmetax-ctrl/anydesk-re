import struct

b = open("/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_inner.exe","rb").read()
e = struct.unpack_from('<I', b, 0x3C)[0]
assert b[e:e+4] == b'PE\x00\x00'
coff = e + 4
machine, nsec, optsz = struct.unpack_from('<HHH', b, coff)[0], struct.unpack_from('<H', b, coff+2)[0], struct.unpack_from('<H', b, coff+16)[0]
opt = coff + 20
magic = struct.unpack_from('<H', b, opt)[0]
imgbase = struct.unpack_from('<I', b, opt+28)[0]
ep = struct.unpack_from('<I', b, opt+16)[0]
print(f"ImageBase=0x{imgbase:x} Entry=0x{ep:x} magic=0x{magic:x} sections={nsec} optsize={optsz}")

sec_off = opt + optsz
sections = []
for i in range(nsec):
    s = sec_off + i*40
    nm = b[s:s+8].rstrip(b'\x00').decode('latin1','replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', b, s+8)
    ch = struct.unpack_from('<I', b, s+36)[0]
    sections.append((nm, vs, va, rs, rp, ch))
    print(f"  {nm:8s} vsize=0x{vs:08x} vaddr=0x{va:08x} rawsize=0x{rs:08x} rawptr=0x{rp:08x} ch=0x{ch:08x}")

def file_to_rva(foff):
    for nm, vs, va, rs, rp, ch in sections:
        if rp <= foff < rp + rs:
            return va + (foff - rp)
    return None

def rva_to_file(rva):
    for nm, vs, va, rs, rp, ch in sections:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

# Key string file offsets (English locale)
targets = {
    "ad.banner.disconnect_countdown": 0x136027b,
    "ad.banner.free":                 0x13604bd,
    "ad.banner.free.default":         0x13604f2,
    "ad.dlg.netinfo.step.waiting":    0x136ec33,
}

print("\n=== String key -> RVA mapping ===")
for name, foff in targets.items():
    rva = file_to_rva(foff)
    va = imgbase + rva if rva else None
    # find the actual key string start (the "ad.banner..." part)
    key_bytes = name.encode()
    idx = b.find(key_bytes, foff - 64, foff + 64)
    if idx >= 0:
        krva = file_to_rva(idx)
        kva = imgbase + krva if krva else None
        print(f"  {name}: key_at=0x{idx:x} rva=0x{krva:x} va=0x{kva:x}")
    else:
        print(f"  {name}: foff=0x{foff:x} rva=0x{rva:x} va=0x{va:x} (key not found nearby)")

# Now search for references to these VAs in the .text section
# The code likely uses push offset / mov reg, offset to reference these strings
print("\n=== Searching for code references ===")
for name, foff in targets.items():
    key_bytes = name.encode()
    idx = b.find(key_bytes, foff - 64, foff + 64)
    if idx < 0:
        continue
    krva = file_to_rva(idx)
    kva = imgbase + krva
    # Search for the VA as a 4-byte little-endian value in the binary
    va_bytes = struct.pack('<I', kva)
    refs = []
    pos = 0
    while True:
        pos = b.find(va_bytes, pos)
        if pos < 0:
            break
        ref_rva = file_to_rva(pos)
        if ref_rva is not None:
            refs.append((pos, ref_rva))
        pos += 1
    print(f"  {name} (va=0x{kva:x}): {len(refs)} refs")
    for foff_ref, rva_ref in refs[:10]:
        print(f"    foff=0x{foff_ref:x} rva=0x{rva_ref:x} va=0x{imgbase+rva_ref:x}")
