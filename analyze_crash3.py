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

md = Cs(CS_ARCH_X86, CS_MODE_32)

# 1. Conditional jump bytes
print("=== Conditional jumps for alternative patches ===")
for va, desc in [(0x1084059e, "block1"), (0x10840680, "block2"), (0x10840768, "block3")]:
    foff = va_to_foff(va)
    raw = b[foff:foff+6]
    # Calculate jump target
    if raw[0] == 0x0f and raw[1] == 0x84:
        offset = struct.unpack_from('<i', raw, 2)[0]
        target = va + 6 + offset
        # Build jmp equivalent
        jmp_offset = target - (va + 5)
        jmp_bytes = b'\xe9' + struct.pack('<i', jmp_offset) + b'\x90'
        print(f"  0x{va:x} [{desc}]: {raw.hex()} (je 0x{target:x}) -> {jmp_bytes.hex()} (jmp 0x{target:x} + nop)")

# 2. Count calls and identify key patterns in 0x10840839-0x10841180
print("\n=== Summary of code after block 3 (0x10840839-0x10841180) ===")
foff = va_to_foff(0x10840839)
chunk = b[foff:foff + 0x947]
call_count = 0
string_refs = []
jmp_targets = set()
for insn in md.disasm(chunk, 0x10840839):
    if insn.mnemonic == 'call':
        call_count += 1
    if insn.mnemonic == 'push' and '0x119' in insn.op_str:
        # String reference
        addr = int(insn.op_str.split('0x')[1].split(',')[0].strip(), 16)
        string_refs.append((insn.address, addr))
    if insn.mnemonic in ('ret', 'retn') and insn.address >= 0x10841180:
        break
    if insn.address >= 0x10841190:
        break

print(f"  Total calls: {call_count}")
print(f"  String references (push 0x119...):")
for addr, str_addr in string_refs:
    # Read the string
    str_foff = va_to_foff(str_addr)
    if str_foff:
        s = b[str_foff:str_foff+80]
        s = s[:s.find(b'\x00')].decode('latin1', 'replace')
        print(f"    0x{addr:x}: push 0x{str_addr:x} -> '{s}'")

# 3. Show the first 30 instructions after block 3
print("\n=== First 40 instructions after block 3 (0x10840839) ===")
foff = va_to_foff(0x10840839)
chunk = b[foff:foff + 200]
count = 0
for insn in md.disasm(chunk, 0x10840839):
    print(f"  0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}")
    count += 1
    if count > 40:
        break

# 4. Check if there's a call to the banner function 0x10840500 in the area
# Also check if 0x10840320 calls 0x10840500
print("\n=== Does function 0x10840320 call 0x10840500? ===")
foff = va_to_foff(0x10840320)
chunk = b[foff:foff + 0x90]  # function is ~0x8c bytes
for insn in md.disasm(chunk, 0x10840320):
    if insn.mnemonic == 'call':
        print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic in ('ret', 'retn'):
        break

# 5. Check what calls function 0x10840320
print("\n=== Callers of 0x10840320 ===")
text_start = sections[0][4]
text_end = text_start + sections[0][3]
target_va = 0x10840320
callers = []
for i in range(text_start, text_end - 5):
    if b[i] == 0xe8:
        rel32 = struct.unpack_from('<i', b, i + 1)[0]
        call_va = i - text_start + imgbase + sections[0][1]
        dest = call_va + 5 + rel32
        if dest == target_va:
            callers.append(call_va)
print(f"  {len(callers)} direct callers")
for c in callers[:10]:
    print(f"    0x{c:x}")

# 6. Check what the crash site 0x1000185F actually is
# Is it in a function? Is it data?
print("\n=== Crash site 0x1000185F context ===")
foff = va_to_foff(0x1000185f)
# Check if this looks like code or data
print(f"  Bytes at 0x1000185f: {b[foff:foff+16].hex()}")
print(f"  Bytes at 0x10001800: {b[foff-0x5f:foff-0x5f+16].hex()}")
# Try to find function start with different prologues
for offset in range(1, 4096):
    check = foff - offset
    if check < sections[0][4]:
        break
    # Check for common prologues
    if b[check:check+3] == b'\x55\x8b\xec':  # push ebp; mov ebp, esp
        func_va = 0x1000185f - offset
        print(f"  Function start (push ebp): 0x{func_va:x} (offset: {offset})")
        break
    if b[check:check+2] == b'\x55\x53':  # push ebp; push ebx
        func_va = 0x1000185f - offset
        print(f"  Possible function start (push ebp; push ebx): 0x{func_va:x} (offset: {offset})")
        break
    if b[check:check+1] == b'\xcc' and b[check+1:check+2] != b'\xcc':
        # After int3 padding
        func_va = 0x1000185f - offset + 1
        print(f"  Possible function start (after int3): 0x{func_va:x} (offset: {offset-1})")
        # Show first instructions
        chunk = b[check+1:foff+20]
        count = 0
        for insn in md.disasm(chunk, func_va):
            marker = " <--- CRASH" if insn.address == 0x1000185f else ""
            print(f"    0x{insn.address:x}: {insn.bytes.hex():<28} {insn.mnemonic} {insn.op_str}{marker}")
            count += 1
            if count > 30:
                break
        break
