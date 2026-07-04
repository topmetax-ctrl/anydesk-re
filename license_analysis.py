"""
Comprehensive license feature analysis for AnyDesk v9.7.8 inner PE.
Finds all license-gated features and their code references.
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

# English string keys for license-gated features
feature_strings = [
    # Connection limits
    b"ad.dlg.closed.conn_limit.message",
    b"ad.dlg.closed.conn_limit.title",
    b"ad.dlg.closed.license_conn_limit.message",
    b"ad.dlg.closed.license_conn_limit.title",
    # Premium feature dialog
    b"ad.dlg.premium.message",
    b"ad.dlg.premium.title",
    b"ad.dlg.premium.title_limited",
    b"ad.dlg.premium.upgrade",
    b"ad.dlg.premium.start_trial",
    b"ad.dlg.premium.try",
    # Session queue limits
    b"ad.session_queue.error.limit",
    # Free user limits (address book)
    b"ad.abook.free_user_limit.add.msg",
    b"ad.abook.free_user_limit.create.msg",
    b"ad.abook.free_user_limit.tag.msg",
    # License status
    b"ad.account.license.upgrade",
    b"ad.account.license.start_trial",
    # Banner
    b"ad.banner.free",
    b"ad.banner.expired.default",
    b"ad.banner.expires.default",
    b"ad.banner.disconnect_countdown",
    # Recording
    b"ad.cfg.recording.incoming",
    b"ad.cfg.recording.outgoing",
    b"ad.cfg.recording.unlock",
    # Privacy
    b"ad.dlg.privacy_not_supported.msg",
    b"ad.dlg.privacy_not_supported.title",
    # Session invitation
    b"ad.dlg.session_invitation_error.feature_disabled",
    # Screen recording disabled
    b"ad.dlg.screen_recording.disabled.msg",
    # Status bar upgrade
    b"ad.status.app.status_bar.upgrade",
]

print("=" * 80)
print("LICENSE FEATURE STRING ANALYSIS")
print("=" * 80)

# Find English versions (look for the key followed by English text)
# English locale strings are typically in the last locale block
# Let's find all occurrences and pick the English ones
for key in feature_strings:
    pos = 0
    locations = []
    while True:
        pos = b.find(key, pos)
        if pos < 0:
            break
        # Read the value after '='
        eq_pos = pos + len(key)
        if eq_pos < len(b) and b[eq_pos:eq_pos+1] == b'=':
            val_start = eq_pos + 1
            val_end = b.find(b'\n', val_start)
            if val_end < 0:
                val_end = val_start + 80
            val = b[val_start:val_end].decode('latin1','replace').strip()
            # Check if it's English (not empty, not accented)
            if val and not any(c in val for c in 'ÃÂå'):
                rva = file_to_rva(pos)
                va = imgbase + rva if rva else 0
                locations.append((pos, va, val))
        pos += 1

    if locations:
        # Pick the English one (usually the one with actual text)
        eng = [l for l in locations if len(l[2]) > 3]
        if eng:
            foff, va, val = eng[-1]  # English is usually last
            print(f"\n  {key.decode()}")
            print(f"    VA=0x{va:x} foff=0x{foff:x}")
            print(f"    Value: {val[:80]}")

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
                print(f"    Code refs: {len(refs)}")
                for foff_ref, va_ref in refs[:5]:
                    print(f"      0x{va_ref:08x} (foff=0x{foff_ref:x})")

# Now find the license type getter function
print("\n" + "=" * 80)
print("LICENSE TYPE GETTER ANALYSIS")
print("=" * 80)

# The config getter at 0x1069af59 - disassemble it
md = Cs(CS_ARCH_X86, CS_MODE_32)
target_va = 0x1069af59
target_foff = rva_to_file(target_va - imgbase)
if target_foff:
    chunk = b[target_foff:target_foff + 200]
    print(f"\n  Config getter at 0x{target_va:x} (foff=0x{target_foff:x}):")
    for insn in md.disasm(chunk, target_va):
        print(f"    0x{insn.address:08x}: {insn.bytes.hex():<30s} {insn.mnemonic:8s} {insn.op_str}")
        if insn.mnemonic == 'ret':
            break

# Find the vtable+0x90 call pattern - search for ff90 or ff5090
print("\n  Searching for [vtable+0x90] calls (call [eax+0x90] / call [edx+0x90]):")
text_rp = sections[0][4]
text_rs = sections[0][3]
text_va = imgbase + sections[0][2]

# Pattern: FF 90 90 00 00 00 (call [eax+0x90]) or FF 52 48 (call [edx+0x48]) etc
# More general: search for call dword ptr [reg + 0x90]
patterns = [
    (b"\xff\x90\x90\x00\x00\x00", "call [eax+0x90]"),
    (b"\xff\x92\x90\x00\x00\x00", "call [edx+0x90]"),
    (b"\xff\x91\x90\x00\x00\x00", "call [ecx+0x90]"),
    (b"\xff\x53\x48", "call [ebx+0x48]"),  # the other vtable call seen
]

for pattern, desc in patterns:
    pos = 0
    refs = []
    while True:
        pos = b.find(pattern, pos)
        if pos < 0:
            break
        ref_rva = file_to_rva(pos)
        if ref_rva is not None and ref_rva < sections[0][2] + sections[0][1]:
            refs.append(imgbase + ref_rva)
        pos += 1
    if refs:
        print(f"    {desc}: {len(refs)} occurrences")
        for va in refs[:10]:
            print(f"      0x{va:08x}")

# Search for config key 0xd (13) - push 0xd followed by call
print("\n  Searching for config key 0xd (push 0xd; call getter):")
# Pattern: 6a 0d ... call
pos = text_rp
count = 0
for i in range(text_rs - 10):
    if b[text_rp + i] == 0x6a and b[text_rp + i + 1] == 0x0d:
        # Check if followed by a call within a few bytes
        for j in range(2, 15):
            if b[text_rp + i + j] == 0xe8:
                va = text_va + i
                count += 1
                if count <= 10:
                    print(f"      0x{va:08x}: push 0xd; ... call")
                break
print(f"    Total: {count}")
