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

def rva_to_file(rva):
    for nm, vs, va, rs, rp in sections:
        if va <= rva < va + max(vs, rs):
            return rp + (rva - va)
    return None

# References found in .text
refs = {
    "disconnect_countdown_1": 0x626166,
    "disconnect_countdown_2": 0x626233,
    "banner_free":            0x6c2b0f,
    "banner_free_default":    0x84d9d2,
    "netinfo_waiting":        0x731345,
    "banner_expired":         0x84db1a,
    "banner_expires":         0x84db01,
}

for name, foff in refs.items():
    rva = file_to_rva(foff)
    va = imgbase + rva
    # Extract 256 bytes before and 128 after the reference point
    start = max(0, foff - 256)
    end = min(len(b), foff + 128)
    chunk = b[start:end]
    start_rva = file_to_rva(start)
    start_va = imgbase + start_rva

    # Write to temp file and disassemble with objdump
    tmp = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
    tmp.write(chunk)
    tmp.close()

    print(f"\n{'='*80}")
    print(f"=== {name} at foff=0x{foff:x} va=0x{va:x} ===")
    print(f"{'='*80}")

    result = subprocess.run(
        ['objdump', '-D', '-b', 'binary', '-m', 'i386', f'--adjust-vma=0x{start_va:x}', tmp.name],
        capture_output=True, text=True
    )
    # Print only lines near the reference (within ~40 lines of the target VA)
    lines = result.stdout.split('\n')
    target_va_str = f"{va:x}"
    for i, line in enumerate(lines):
        if target_va_str in line.lower():
            for j in range(max(0,i-15), min(len(lines), i+10)):
                print(lines[j])
            break
    os.unlink(tmp.name)
