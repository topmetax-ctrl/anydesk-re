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

md = Cs(CS_ARCH_X86, CS_MODE_32)

def disasm_around(foff, before, after, label, outfile):
    rva = file_to_rva(foff)
    va = imgbase + rva
    start = max(0, foff - before)
    end = min(len(b), foff + after)
    chunk = b[start:end]
    start_va = imgbase + file_to_rva(start)

    outfile.write(f"\n{'='*80}\n")
    outfile.write(f"=== {label} at va=0x{va:x} (foff=0x{foff:x}) ===\n")
    outfile.write(f"{'='*80}\n")
    for insn in md.disasm(chunk, start_va):
        marker = " <--- REF" if insn.address == va else ""
        outfile.write(f"  0x{insn.address:08x}: {insn.bytes.hex():<34s} {insn.mnemonic:8s} {insn.op_str}{marker}\n")

with open("/tmp/anydesk_disasm.txt","w") as f:
    # disconnect_countdown - both refs, wide window
    disasm_around(0x626166, 600, 400, "disconnect_countdown_1", f)
    disasm_around(0x626233, 50, 300, "disconnect_countdown_2", f)
    # banner_free
    disasm_around(0x6c2b0f, 400, 200, "banner_free", f)
    # banner_free_default
    disasm_around(0x84d9d2, 400, 300, "banner_free_default", f)
    # netinfo_waiting
    disasm_around(0x731345, 400, 200, "netinfo_waiting", f)
    # banner_expired + expires (close together)
    disasm_around(0x84db01, 300, 200, "banner_expires+expired", f)

print("wrote /tmp/anydesk_disasm.txt")
