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
rdata_start = sections[1][4]
rdata_end = rdata_start + sections[1][3]
md = Cs(CS_ARCH_X86, CS_MODE_32)

# 1. Full epilogue at 0x10841180
print("=== Banner function epilogue 0x10841180-0x10841190 ===")
foff = va_to_foff(0x10841180)
chunk = b[foff:foff + 30]
for insn in md.disasm(chunk, 0x10841180):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic in ('ret', 'retn'):
        break

# 2. Parse ALL imports to find SetTimer
print("\n=== All USER32 imports with Timer ===")
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
                print(f"  DLL: {dll_name}")
                iat_foff = None
                ilt_foff = None
                for nm2, vs2, va2, rs2, rp2 in sections:
                    if rp2 <= iat_rva and iat_rva < rp2 + rs2:
                        iat_foff = rp2 + (iat_rva - va2)
                    if rp2 <= ilt_rva and ilt_rva < rp2 + rs2:
                        ilt_foff = rp2 + (ilt_rva - va2)
                if iat_foff and ilt_foff:
                    j = 0
                    while True:
                        entry = struct.unpack_from('<I', b, ilt_foff + j * 4)[0]
                        if entry == 0:
                            break
                        iat_va = iat_rva + j * 4
                        if entry & 0x80000000:
                            ordinal = entry & 0xFFFF
                            print(f"    Ordinal {ordinal}: IAT VA = 0x{iat_va:x}")
                        else:
                            hint_foff = None
                            for nm2, vs2, va2, rs2, rp2 in sections:
                                if rp2 <= entry and entry < rp2 + rs2:
                                    hint_foff = rp2 + (entry - va2)
                                    break
                            if hint_foff:
                                func_name = b[hint_foff+2:b.find(b'\x00', hint_foff+2)].decode('latin1', 'replace')
                                print(f"    {func_name}: IAT VA = 0x{iat_va:x}")
                        j += 1
        idx += 1

# 3. Search for call to IAT pattern (ff 15 xx xx xx xx) near push 0xF4240
# First find all SetTimer/KillTimer IAT entries
print("\n=== Search for SetTimer/KillTimer in all imports ===")
all_timer_iats = []
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
            iat_foff = None
            ilt_foff = None
            for nm2, vs2, va2, rs2, rp2 in sections:
                if rp2 <= iat_rva and iat_rva < rp2 + rs2:
                    iat_foff = rp2 + (iat_rva - va2)
                if rp2 <= ilt_rva and ilt_rva < rp2 + rs2:
                    ilt_foff = rp2 + (ilt_rva - va2)
            if iat_foff and ilt_foff:
                j = 0
                while True:
                    entry = struct.unpack_from('<I', b, ilt_foff + j * 4)[0]
                    if entry == 0:
                        break
                    iat_va = iat_rva + j * 4
                    if not (entry & 0x80000000):
                        hint_foff = None
                        for nm2, vs2, va2, rs2, rp2 in sections:
                            if rp2 <= entry and entry < rp2 + rs2:
                                hint_foff = rp2 + (entry - va2)
                                break
                        if hint_foff:
                            func_name = b[hint_foff+2:b.find(b'\x00', hint_foff+2)].decode('latin1', 'replace')
                            if 'timer' in func_name.lower() or 'Timer' in func_name:
                                print(f"  {func_name} ({dll_name}): IAT VA = 0x{iat_va:x}")
                                all_timer_iats.append((func_name, iat_va))
                    j += 1
        idx += 1

# 4. For each timer IAT, find call sites (ff 15 xx xx xx xx)
print("\n=== Call sites for timer IAT entries ===")
for func_name, iat_va in all_timer_iats:
    call_pattern = b'\xff\x15' + struct.pack('<I', iat_va)
    pos = text_start
    callers = []
    while pos < text_end - 6:
        pos = b.find(call_pattern, pos, text_end)
        if pos < 0:
            break
        call_va = foff_to_va(pos)
        callers.append(call_va)
        pos += 1
    print(f"\n  {func_name} (IAT 0x{iat_va:x}): {len(callers)} call sites")
    for c in callers[:20]:
        # Show 10 instructions before and 3 after
        ctx_foff = va_to_foff(c - 40)
        chunk = b[ctx_foff:ctx_foff + 60]
        print(f"\n    Call at 0x{c:x}:")
        for insn in md.disasm(chunk, c - 40):
            marker = " <--- CALL" if insn.address == c else ""
            print(f"      0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
            if insn.address > c + 6:
                break

# 5. Also check what 0x111d2bd0 and 0x111d2ed8 are (calls after push 0xF4240)
print("\n=== Functions called after push 0xF4240 ===")
for target in [0x111d2bd0, 0x111d2ed8, 0x1109fc97]:
    foff = va_to_foff(target)
    print(f"\n  0x{target:x}:")
    print(f"    Raw: {b[foff:foff+20].hex()}")
    for insn in md.disasm(b[foff:foff+40], target):
        print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
        if insn.address > target + 30:
            break
