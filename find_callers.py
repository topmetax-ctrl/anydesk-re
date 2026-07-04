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

# .text section boundaries
text_rp = sections[0][4]
text_rs = sections[0][3]
text_va = imgbase + sections[0][2]
text_data = b[text_rp:text_rp+text_rs]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# 1. Find callers of banner function 0x1084e520 and banner constructor 0x106c35b0
# 2. Find callers of countdown function 0x10626b70
# 3. Find Sleep/SetTimer calls

targets = {
    0x1084e520: "banner_formatter",
    0x106c35b0: "banner_constructor",
    0x10626b70: "countdown_handler",
}

print("=== Searching for callers (call/jmp to target functions) ===")
for insn in md.disasm(text_data, text_va):
    if insn.mnemonic in ('call', 'jmp') and len(insn.operands) == 1:
        op = insn.operands[0]
        if op.type == 2:  # immediate
            target = op.imm
            if target in targets:
                rva = insn.address - imgbase
                foff = rva_to_file(rva)
                print(f"  {targets[target]} called from 0x{insn.address:08x} (foff=0x{foff:x})")

# Also search for Sleep import and SetTimer
print("\n=== Searching for Sleep/SetTimer/SetWaitableTimer references ===")
# Look for indirect calls through IAT - search for call dword ptr [addr]
# First find kernel32.dll imports
idata_dir = opt + 96 + 1*8  # import directory RVA
import_rva = struct.unpack_from('<I', b, idata_dir)[0]
import_size = struct.unpack_from('<I', b, idata_dir+4)[0]
print(f"  Import directory RVA=0x{import_rva:x} size=0x{import_size:x}")

# Parse import directory
imp_foff = rva_to_file(import_rva)
if imp_foff:
    idx = 0
    while True:
        desc = b[imp_foff + idx*20: imp_foff + idx*20 + 20]
        ilt, ts, fwd, name_rva, iat = struct.unpack('<IIIII', desc)
        if ilt == 0 and name_rva == 0:
            break
        name_foff = rva_to_file(name_rva)
        if name_foff:
            dll_name = b[name_foff:b.find(b'\x00', name_foff)].decode('latin1','replace')
            if 'kernel' in dll_name.lower() or 'user' in dll_name.lower():
                print(f"  DLL: {dll_name} ILT=0x{ilt:x} IAT=0x{iat:x}")
                # Parse IAT entries
                iat_foff = rva_to_file(iat)
                ilt_foff = rva_to_file(ilt)
                func_idx = 0
                while True:
                    entry = struct.unpack_from('<I', b, ilt_foff + func_idx*4)[0]
                    if entry == 0:
                        break
                    if entry & 0x80000000:
                        func_name = f"#{entry & 0x7FFFFFFF}"
                    else:
                        hint_foff = rva_to_file(entry)
                        if hint_foff:
                            fn = b[hint_foff+2:b.find(b'\x00', hint_foff+2)].decode('latin1','replace')
                            func_name = fn
                        else:
                            func_name = "?"
                    iat_entry_va = imgbase + iat + func_idx*4
                    if func_name in ('Sleep', 'SetTimer', 'SetWaitableTimer', 'CreateWaitableTimerW', 'CreateWaitableTimerA', 'MsgWaitForMultipleObjects', 'WaitForSingleObject', 'WaitForSingleObjectEx'):
                        print(f"    {func_name} -> IAT VA=0x{iat_entry_va:x}")
                        # Search for references to this IAT entry
                        iat_bytes = struct.pack('<I', iat_entry_va)
                        pos = 0
                        refs = []
                        while True:
                            pos = b.find(iat_bytes, pos)
                            if pos < 0:
                                break
                            ref_rva = file_to_rva(pos)
                            if ref_rva is not None and ref_rva < sections[0][2] + sections[0][1]:
                                refs.append((pos, imgbase+ref_rva))
                            pos += 1
                        print(f"      {len(refs)} refs in .text")
                        for foff_ref, va_ref in refs[:8]:
                            print(f"        0x{va_ref:08x} (foff=0x{foff_ref:x})")
                    func_idx += 1
        idx += 1
