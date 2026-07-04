#!/usr/bin/env python3
"""
AnyDesk win_loader payload decoder.

The AnyDesk.exe is a small "win_loader" stub (PDB path leaked:
  C:\Gitlab-Runner\builds\T4hxUfUPM\0\anydesk\anydesk\release\app-32\win_loader\Static\AnyDesk.pdb)

Architecture:
  - .text  ~10KB  : loader stub (no IAT, resolves APIs by hash via PEB walk)
  - .data  ~8.2MB : ENCRYPTED payload (the real AnyDesk PE), XOR-stream cipher
  - .rdata ~1KB   : slots for resolved API function pointers + hashes

Decryption routine found at 0x4033f4 (disasm):
    mov  edx, 0x2129000   ; dest = start of .data (VMA)
    mov  ecx, 0x55F4      ; seed
    mov  esi, 0x7E3A1A    ; length = 8,271,898 bytes
  loop:
    imul ecx, ecx, 0x19660D     ; LCG multiply (Numerical Recipes rand)
    add  ecx, 0x3C6EF35F        ; LCG increment
    mov  eax, ecx
    shr  eax, 12                ; key byte = (state >> 12) & 0xFF
    xor  [edx], al
    inc  edx
    dec  esi
    jne  loop

So it is a reversible LCG-based XOR stream cipher. Because XOR is symmetric,
running the same routine again re-encrypts; running it on the ciphertext
yields the plaintext payload (a PE that starts with "MZ", confirmed by the
loader's MZ check at 0x401070).

This script reproduces that routine offline to recover the inner PE.
"""

import struct
import sys

MULT = 0x19660D
ADD  = 0x3C6EF35F
SEED = 0x55F4
LEN  = 0x7E3A1A
DATA_VMA = 0x2129000


def find_section(pe_bytes, name):
    # DOS header
    e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    # PE signature + COFF header
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", pe_bytes, coff + 2)[0]
    size_opt = struct.unpack_from("<H", pe_bytes, coff + 16)[0]
    sec_off = coff + 20 + size_opt
    for i in range(num_sections):
        s = sec_off + i * 40
        sname = pe_bytes[s:s + 8].rstrip(b"\x00").decode("latin1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", pe_bytes, s + 8)
        if sname == name:
            return dict(name=sname, vsize=vsize, vaddr=vaddr,
                        rawsize=rawsize, rawptr=rawptr, off=s)
    return None


def lcg_xor_stream(data, seed=SEED, length=LEN):
    state = seed
    out = bytearray(data)
    n = min(length, len(out))
    for i in range(n):
        state = (state * MULT + ADD) & 0xFFFFFFFF
        out[i] ^= (state >> 12) & 0xFF
    return bytes(out)


def pe_info(b):
    if b[:2] != b"MZ":
        return "NOT a PE (no MZ)"
    e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
    if b[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return "MZ ok, but no PE signature"
    coff = e_lfanew + 4
    machine = struct.unpack_from("<H", b, coff)[0]
    nsec = struct.unpack_from("<H", b, coff + 2)[0]
    opt_off = coff + 20
    magic = struct.unpack_from("<H", b, opt_off)[0]
    ep = struct.unpack_from("<I", b, opt_off + 16)[0]
    imgbase = struct.unpack_from("<I", b, opt_off + 28)[0]
    subsys = struct.unpack_from("<H", b, opt_off + 68)[0]
    return (f"PE{'32+' if magic==0x20b else '32'} machine=0x{machine:04x} "
            f"sections={nsec} entry=0x{ep:x} imgbase=0x{imgbase:x} subsys={subsys}")


def main():
    src = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk.exe"
    with open(src, "rb") as f:
        pe = f.read()
    print(f"[*] loader size: {len(pe)} bytes")

    data = find_section(pe, ".data")
    rdata = find_section(pe, ".rdata")
    text = find_section(pe, ".text")
    print(f"[*] .text  vaddr=0x{text['vaddr']:x} rawptr=0x{text['rawptr']:x} rawsize=0x{text['rawsize']:x}")
    print(f"[*] .rdata vaddr=0x{rdata['vaddr']:x} rawptr=0x{rdata['rawptr']:x} rawsize=0x{rdata['rawsize']:x}")
    print(f"[*] .data  vaddr=0x{data['vaddr']:x} rawptr=0x{data['rawptr']:x} rawsize=0x{data['rawsize']:x}")
    print(f"[*] .data VMA 0x{data['vaddr']:x} == decrypt dest 0x{DATA_VMA:x}? {data['vaddr'] == DATA_VMA}")
    print(f"[*] decrypt length = 0x{LEN:x} ({LEN} bytes); .data rawsize = 0x{data['rawsize']:x}")

    enc = pe[data['rawptr']:data['rawptr'] + LEN]
    print(f"[*] read {len(enc)} encrypted bytes from .data")

    dec = lcg_xor_stream(enc)
    print(f"[*] first 16 bytes after decode: {dec[:16].hex(' ')}")
    print(f"[*] PE check: {pe_info(dec)}")

    out = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_inner_decoded.bin"
    with open(out, "wb") as f:
        f.write(dec)
    print(f"[+] wrote decoded payload to {out} ({len(dec)} bytes)")

    # also dump a few printable strings from the head to confirm it is AnyDesk
    import re
    strs = re.findall(rb"[\x20-\x7e]{6,}", dec[:0x20000])
    print("[*] sample strings near start of decoded payload:")
    for s in strs[:25]:
        print("     ", s.decode("latin1"))


if __name__ == "__main__":
    main()
