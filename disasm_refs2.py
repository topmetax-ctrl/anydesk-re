import struct, subprocess, tempfile, os

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

refs = [
    ("disconnect_countdown_1", 0x626166),
    ("disconnect_countdown_2", 0x626233),
    ("banner_free",            0x6c2b0f),
    ("banner_free_default",    0x84d9d2),
    ("netinfo_waiting",        0x731345),
    ("banner_expired",         0x84db1a),
    ("banner_expires",         0x84db01),
]

for name, foff in refs:
    rva = file_to_rva(foff)
    va = imgbase + rva
    start = max(0, foff - 128)
    end = min(len(b), foff + 64)
    chunk = b[start:end]
    start_rva = file_to_rva(start)
    start_va = imgbase + start_rva

    tmp = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
    tmp.write(chunk)
    tmp.close()

    result = subprocess.run(
        ['objdump', '-D', '-b', 'binary', '-m', 'i386', f'--adjust-vma=0x{start_va:x}', tmp.name],
        capture_output=True, text=True
    )
    print(f"\n{'='*70}")
    print(f"=== {name} at va=0x{va:x} (foff=0x{foff:x}) ===")
    print(f"{'='*70}")
    # Print all disasm lines
    for line in result.stdout.split('\n'):
        if ':' in line and '\t' in line:
            print(line)
    os.unlink(tmp.name)
