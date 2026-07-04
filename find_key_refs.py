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
    vs, va, rs, rp = struct.unpack_from('<IIII', b, s+8)
    sections.append((vs, va, rs, rp))

def f2r(f):
    for vs, va, rs, rp in sections:
        if rp <= f < rp + rs:
            return va + (f - rp)
    return None

keys = [
    b"ad.dlg.premium.title\x00",
    b"ad.dlg.closed.license_conn_limit.message\x00",
    b"ad.dlg.closed.conn_limit.message\x00",
    b"ad.session_queue.error.limit\x00",
    b"ad.abook.free_user_limit.add.msg\x00",
    b"ad.dlg.screen_recording.disabled.msg\x00",
    b"ad.dlg.session_invitation_error.feature_disabled\x00",
]

rdata_rp = sections[1][3]
rdata_rs = sections[1][2]

for key in keys:
    pos = rdata_rp
    found = False
    while pos < rdata_rp + rdata_rs:
        pos = b.find(key, pos, rdata_rp + rdata_rs)
        if pos < 0:
            break
        rva = f2r(pos)
        va = imgbase + rva
        va_bytes = struct.pack('<I', va)
        # Count refs in .text
        p2 = 0
        refs = []
        while True:
            p2 = b.find(va_bytes, p2)
            if p2 < 0:
                break
            r2 = f2r(p2)
            if r2 is not None and r2 < sections[0][1] + sections[0][0]:
                refs.append(imgbase + r2)
            p2 += 1
        ks = key.rstrip(b'\x00').decode()
        print(f"{ks}: VA=0x{va:x} refs={len(refs)}")
        for r in refs[:5]:
            print(f"  0x{r:08x}")
        found = True
        pos += 1
    if not found:
        print(f"{key.rstrip(b'\x00').decode()}: NOT FOUND in .rdata")
