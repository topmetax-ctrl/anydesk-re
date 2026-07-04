"""
The string VA references didn't match because the strings are referenced
by their KEY (e.g. "ad.dlg.premium.title") not by the value VA.
The code pushes a pointer to the KEY string, then calls a locale lookup function.
Let's find the key string VAs and their references.
"""
import struct
from capstone import *

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

md = Cs(CS_ARCH_X86, CS_MODE_32)

# Find the KEY strings (not values) in .rdata
# These are the string table keys that get pushed as arguments
keys = [
    b"ad.dlg.premium.title\x00",
    b"ad.dlg.premium.message\x00",
    b"ad.dlg.closed.license_conn_limit.message\x00",
    b"ad.dlg.closed.license_conn_limit.title\x00",
    b"ad.dlg.closed.conn_limit.message\x00",
    b"ad.dlg.closed.conn_limit.title\x00",
    b"ad.session_queue.error.limit\x00",
    b"ad.abook.free_user_limit.add.msg\x00",
    b"ad.dlg.premium.upgrade\x00",
    b"ad.dlg.screen_recording.disabled.msg\x00",
    b"ad.dlg.session_invitation_error.feature_disabled\x00",
]

print("=== Key string locations and code references ===\n")
for key in keys:
    # Find in .rdata section
    rdata_rp = sections[1][4]
    rdata_rs = sections[1][3]
    rdata_va = imgbase + sections[1][2]
    
    pos = rdata_rp
    found = False
    while pos < rdata_rp + rdata_rs:
        pos = b.find(key, pos, rdata_rp + rdata_rs)
        if pos < 0:
            break
        rva = file_to_rva(pos)
        va = imgbase + rva if rva else 0
        # Search for VA references in .text
        va_bytes = struct.pack('<I', va)
        pos2 = 0
        refs = []
        while True:
            pos2 = b.find(va_bytes, pos2)
            if pos2 < 0:
                break
            ref_rva = file_to_rva(pos2)
            if ref_rva is not None and ref_rva < sections[0][2] + sections[0][1]:
                refs.append((pos2, imgbase + ref_rva))
            pos2 += 1
        if refs:
            found = True
            key_str = key.rstrip(b'\x00').decode()
            print(f"  {key_str}")
            print(f"    Key VA=0x{va:x}, {len(refs)} code refs:")
            for foff, va_ref in refs[:5]:
                print(f"      0x{va_ref:08x} (foff=0x{foff:x})")
                # Disassemble 100 bytes before to find function start
                start = max(0, foff - 150)
                chunk = b[start:foff + 50]
                start_va = imgbase + file_to_rva(start)
                # Find push ebp; mov ebp,esp before the ref
                for insn in md.disasm(chunk, start_va):
                    if insn.address == va_ref:
                        # Show a few instructions before
                        pass
                # Just show 20 bytes before and 20 after
                pre = b[max(0,foff-20):foff]
                post = b[foff:foff+20]
                pre_insns = list(md.disasm(pre, imgbase + file_to_rva(max(0,foff-20))))
                post_insns = list(md.disasm(post, va_ref))
                for insn in pre_insns[-3:]:
                    print(f"        PRE: 0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
                for insn in post_insns[:3]:
                    print(f"        POST: 0x{insn.address:08x}: {insn.mnemonic} {insn.op_str}")
        pos += 1
    if not found:
        print(f"  {key.rstrip(b chr(0)).decode()}: NO refs found")
