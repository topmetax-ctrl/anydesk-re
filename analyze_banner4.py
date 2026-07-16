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
md = Cs(CS_ARCH_X86, CS_MODE_32)

# 1. Banner function epilogue at 0x10841180
print("=== Banner function epilogue at 0x10841180 ===")
foff = va_to_foff(0x10841180)
chunk = b[foff:foff + 80]
for insn in md.disasm(chunk, 0x10841180):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic in ('ret', 'retn'):
        break

# 2. Banner function first bytes
print("\n=== Banner function 0x10840500 first 20 bytes ===")
foff = va_to_foff(0x10840500)
print(f"  Raw: {b[foff:foff+10].hex()}")
for insn in md.disasm(b[foff:foff+30], 0x10840500):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")

# 3. Check the je at 0x10840537
print("\n=== je at 0x10840537 (skip to epilogue) ===")
foff = va_to_foff(0x10840537)
print(f"  Raw: {b[foff:foff+6].hex()}")
for insn in md.disasm(b[foff:foff+6], 0x10840537):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")

# 4. Function 0x10838550 - first 100 instructions
print("\n=== Function 0x10838550 (license_banner_type) ===")
foff = va_to_foff(0x10838550)
chunk = b[foff:foff + 500]
count = 0
for insn in md.disasm(chunk, 0x10838550):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    count += 1
    if count > 60:
        print("  ... (truncated)")
        break

# 5. Find SetTimer IAT by parsing import directory
print("\n=== SetTimer IAT lookup ===")
# Parse import directory
import_dir_rva = struct.unpack_from('<I', b, opt + 104)[0]
import_dir_foff = None
for nm, vs, va, rs, rp in sections:
    if rp <= import_dir_rva and import_dir_rva < rp + rs:
        import_dir_foff = rp + (import_dir_rva - va)
        break

if import_dir_foff:
    idx = 0
    while True:
        desc_off = import_dir_foff + idx * 20
        ilt_rva = struct.unpack_from('<I', b, desc_off)[0]
        name_rva = struct.unpack_from('<I', b, desc_off + 12)[0]
        iat_rva = struct.unpack_from('<I', b, desc_off + 16)[0]
        if ilt_rva == 0 and name_rva == 0:
            break
        # Get DLL name
        name_foff = None
        for nm, vs, va, rs, rp in sections:
            if rp <= name_rva and name_rva < rp + rs:
                name_foff = rp + (name_rva - va)
                break
        if name_foff:
            dll_name = b[name_foff:b.find(b'\x00', name_foff)].decode('latin1', 'replace')
            if 'user32' in dll_name.lower():
                print(f"  Found {dll_name} import")
                # Parse IAT entries
                iat_foff = None
                for nm2, vs2, va2, rs2, rp2 in sections:
                    if rp2 <= iat_rva and iat_rva < rp2 + rs2:
                        iat_foff = rp2 + (iat_rva - va2)
                        break
                ilt_foff = None
                for nm2, vs2, va2, rs2, rp2 in sections:
                    if rp2 <= ilt_rva and ilt_rva < rp2 + rs2:
                        ilt_foff = rp2 + (ilt_rva - va2)
                        break
                if iat_foff and ilt_foff:
                    j = 0
                    while True:
                        entry = struct.unpack_from('<I', b, ilt_foff + j * 4)[0]
                        if entry == 0:
                            break
                        if not (entry & 0x80000000):  # by name
                            hint_rva = entry
                            hint_foff = None
                            for nm2, vs2, va2, rs2, rp2 in sections:
                                if rp2 <= hint_rva and hint_rva < rp2 + rs2:
                                    hint_foff = rp2 + (hint_rva - va2)
                                    break
                            if hint_foff:
                                func_name = b[hint_foff+2:b.find(b'\x00', hint_foff+2)].decode('latin1', 'replace')
                                iat_va = iat_rva + j * 4
                                if 'Timer' in func_name or 'timer' in func_name:
                                    print(f"    {func_name}: IAT VA = 0x{iat_va:x}")
                        j += 1
        idx += 1

# 6. Check 0x10d83764 - find its function
print("\n=== 0x10d83764 function context ===")
foff = va_to_foff(0x10d83764)
for offset in range(1, 4096):
    check = foff - offset
    if b[check:check+3] == b'\x55\x8b\xec':
        func_start = 0x10d83764 - offset
        print(f"  Function start: 0x{func_start:x} (offset: {offset})")
        # Show first 20 instructions
        chunk = b[check:check + 200]
        count = 0
        for insn in md.disasm(chunk, func_start):
            marker = " <--- BAD PATCH" if insn.address == 0x10d83764 else ""
            print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
            count += 1
            if count > 25 or insn.address > 0x10d83780:
                break
        break
