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

# 1. Search for both SetTimer IAT patterns
print("=== SetTimer call sites ===")
for iat_va in [0x110af718, 0x110af794]:
    pattern = b'\xff\x15' + struct.pack('<I', iat_va)
    pos = text_start
    callers = []
    while pos < text_end - 6:
        pos = b.find(pattern, pos, text_end)
        if pos < 0:
            break
        call_va = foff_to_va(pos)
        callers.append(call_va)
        pos += 1
    print(f"\n  IAT 0x{iat_va:x}: {len(callers)} call sites")
    for c in callers[:10]:
        ctx_foff = va_to_foff(c - 30)
        chunk = b[ctx_foff:ctx_foff + 50]
        print(f"    Call at 0x{c:x}:")
        for insn in md.disasm(chunk, c - 30):
            marker = " <---" if insn.address == c else ""
            print(f"      0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
            if insn.address > c + 6:
                break

# 2. Verify the correct SetTimer IAT by checking import names more carefully
print("\n=== Verify SetTimer IAT ===")
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
        name_foff = None
        for nm, vs, va, rs, rp in sections:
            if rp <= name_rva and name_rva < rp + rs:
                name_foff = rp + (name_rva - va)
                break
        if name_foff:
            dll_name = b[name_foff:b.find(b'\x00', name_foff)].decode('latin1', 'replace')
            if 'user32' in dll_name.lower():
                print(f"  DLL: {dll_name}, ILT RVA=0x{ilt_rva:x}, IAT RVA=0x{iat_rva:x}")
                ilt_foff = None
                for nm2, vs2, va2, rs2, rp2 in sections:
                    if rp2 <= ilt_rva and ilt_rva < rp2 + rs2:
                        ilt_foff = rp2 + (ilt_rva - va2)
                        break
                if ilt_foff:
                    j = 0
                    while True:
                        entry = struct.unpack_from('<I', b, ilt_foff + j * 4)[0]
                        if entry == 0:
                            break
                        iat_va_full = imgbase + iat_rva + j * 4
                        if entry & 0x80000000:
                            ordinal = entry & 0xFFFF
                            print(f"    Ordinal {ordinal}: IAT VA = 0x{iat_va_full:x}")
                        else:
                            hint_foff = None
                            for nm2, vs2, va2, rs2, rp2 in sections:
                                if rp2 <= entry and entry < rp2 + rs2:
                                    hint_foff = rp2 + (entry - va2)
                                    break
                            if hint_foff:
                                func_name = b[hint_foff+2:b.find(b'\x00', hint_foff+2)].decode('latin1', 'replace')
                                if 'imer' in func_name or 'IMER' in func_name:
                                    print(f"    {func_name}: IAT VA = 0x{iat_va_full:x} (RVA=0x{iat_rva + j * 4:x})")
                        j += 1
        idx += 1

# 3. Search for KillTimer call sites too
print("\n=== KillTimer call sites ===")
for iat_va in [0x110af714, 0x110af790, 0x110af798]:
    pattern = b'\xff\x15' + struct.pack('<I', iat_va)
    pos = text_start
    count = 0
    while pos < text_end - 6:
        pos = b.find(pattern, pos, text_end)
        if pos < 0:
            break
        count += 1
        pos += 1
    if count > 0:
        print(f"  IAT 0x{iat_va:x}: {count} call sites")

# 4. Look at the 0x10c66a80 location more carefully - is it really code?
print("\n=== Check if 0x10c66a80 is in .text ===")
foff = va_to_foff(0x10c66a80)
in_text = text_start <= foff < text_end
print(f"  foff=0x{foff:x}, in .text: {in_text}")
if in_text:
    # Find function start
    for offset in range(1, 4096):
        check = foff - offset
        if b[check:check+3] == b'\x55\x8b\xec':
            func_start = 0x10c66a80 - offset
            print(f"  Function start: 0x{func_start:x}")
            # Show instructions around push 0xF4240
            ctx_foff = va_to_foff(0x10c66a60)
            chunk = b[ctx_foff:ctx_foff + 80]
            for insn in md.disasm(chunk, 0x10c66a60):
                marker = " <---" if insn.address == 0x10c66a80 else ""
                print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
                if insn.address > 0x10c66aa0:
                    break
            break

# 5. Check 0x10c66d83 function context
print("\n=== Check 0x10c66d83 function context ===")
foff = va_to_foff(0x10c66d83)
for offset in range(1, 4096):
    check = foff - offset
    if b[check:check+3] == b'\x55\x8b\xec':
        func_start = 0x10c66d83 - offset
        print(f"  Function start: 0x{func_start:x}")
        ctx_foff = va_to_foff(0x10c66d60)
        chunk = b[ctx_foff:ctx_foff + 80]
        for insn in md.disasm(chunk, 0x10c66d60):
            marker = " <---" if insn.address == 0x10c66d83 else ""
            print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
            if insn.address > 0x10c66da0:
                break
        break

# 6. Search for the string "ad.session.timeout" or "session_timeout" in rdata
print("\n=== session_timeout strings ===")
rdata_start = sections[1][4]
rdata_end = rdata_start + sections[1][3]
for pattern in [b'session_timeout', b'session.timeout', b'sessionTimeout']:
    pos = rdata_start
    while pos < rdata_end:
        pos = b.find(pattern, pos, rdata_end)
        if pos < 0:
            break
        start = pos
        while start > rdata_start and b[start-1] != 0:
            start -= 1
        end = b.find(b'\x00', pos, pos + 200)
        full = b[start:end].decode('latin1', 'replace')
        if len(full) < 100:
            va = foff_to_va(start)
            print(f"  0x{va:08x}: '{full[:80]}'")
        pos += 1
