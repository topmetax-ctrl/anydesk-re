"""
AnyDesk v9.7.8 patcher.
Removes:
  1. Disconnect countdown timer ("Session will be closed in %d %s...")
  2. Free license / trial banner ads

Pipeline:
  1. Decode outer AnyDesk.exe (XOR decrypt + LZMA1 decompress) -> inner PE
  2. Patch inner PE (3 byte-level patches)
  3. Re-encode (LZMA1 compress + XOR encrypt) -> new AnyDesk.exe
"""
import struct, lzma, time, os

SRC = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk.exe"
OUT = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_patched.exe"

# --- Crypto constants (from loader stub at 0x4033f4) ---
MULT = 0x19660D
ADD  = 0x3C6EF35F
SEED = 0x55F4
ENC_LEN = 0x7E3A1A       # hardcoded decrypt length in loader
DATA_RAWPTR = 0x3400     # .data section file offset in outer PE
LZMA_PROPS = 0x5D
LZMA_DICT  = 0x04000000

# --- Inner PE patch points (VA -> file offset) ---
# ImageBase = 0x10000000, .text vaddr=0x1000 rawptr=0x400
# VA to file offset: foff = VA - 0x10000000 - 0x1000 + 0x400 = VA - 0x1000C00
def va_to_foff(va):
    return va - 0x10000000 - 0x1000 + 0x400

PATCHES = [
    # 1. Countdown switch: always take case_0 (skip countdown timer)
    #    VA 0x10626bbb: sub eax,0 (83 e8 00) -> xor eax,eax; nop (33 c0 90)
    {
        "name": "countdown_skip",
        "va": 0x10626bbb,
        "expected": b"\x83\xe8\x00",
        "patch": b"\x33\xc0\x90",
        "desc": "Skip disconnect countdown timer (always case_0)"
    },
    # 2. Banner constructor: NOP the UI add call
    #    VA 0x106c376f: call 0x10d83764 (e8 f0 ff 6b 00) -> 5x NOP
    {
        "name": "banner_no_ui_add",
        "va": 0x106c376f,
        "expected": b"\xe8\xf0\xff\x6b\x00",
        "patch": b"\x90\x90\x90\x90\x90",
        "desc": "Prevent banner from being added to UI"
    },
    # 3. Banner formatter: return immediately
    #    VA 0x1084e520: push ebp; mov ebp,esp (55 8b ec) -> xor eax,eax; ret 0x10
    #    4 stack params (ret 0x10 = 16 bytes)
    {
        "name": "banner_formatter_ret",
        "va": 0x1084e520,
        "expected": b"\x55\x8b\xec",
        "patch": b"\x33\xc0\xc2\x10\x00",
        "desc": "Banner formatter returns immediately (no banner text)"
    },
]


def lcg_xor(data, seed=SEED):
    """LCG-based XOR stream cipher (symmetric)."""
    out = bytearray(data)
    s = seed
    for i in range(len(out)):
        s = (s * MULT + ADD) & 0xFFFFFFFF
        out[i] ^= (s >> 12) & 0xFF
    return bytes(out)


def decode_outer(raw):
    """Decode outer PE -> inner PE."""
    # Read decrypt length from loader code (mov esi, imm32 at foff 0x2800)
    enc_len = struct.unpack_from('<I', raw, 0x2800)[0]
    enc = raw[DATA_RAWPTR:DATA_RAWPTR + enc_len]
    decrypted = lcg_xor(enc)
    # LZMA1 decompress (skip 5-byte header: props + dict_size)
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                filters=[{"id": lzma.FILTER_LZMA1,
                                          "dict_size": LZMA_DICT,
                                          "lc": 3, "lp": 0, "pb": 2}])
    inner = dec.decompress(decrypted[5:])
    return inner


def encode_inner(inner):
    """Encode inner PE -> encrypted .data payload."""
    # LZMA1 compress (raw, no header)
    comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW,
                               filters=[{"id": lzma.FILTER_LZMA1,
                                         "dict_size": LZMA_DICT,
                                         "lc": 3, "lp": 0, "pb": 2}])
    compressed = comp.compress(inner) + comp.flush()
    # Prepend 5-byte header: props(1) + dict_size(4 LE)
    header = bytes([LZMA_PROPS]) + struct.pack('<I', LZMA_DICT)
    payload = header + compressed
    print(f"  LZMA compressed: {len(inner)} -> {len(payload)} bytes")
    # XOR encrypt
    encrypted = lcg_xor(payload)
    return encrypted, len(payload)


def main():
    t0 = time.time()
    print(f"[*] Reading {SRC}")
    raw = open(SRC, "rb").read()
    print(f"    outer PE: {len(raw)} bytes")

    # Stage 1: Decode
    print("[*] Stage 1: Decoding (XOR + LZMA1)")
    inner = decode_outer(raw)
    print(f"    inner PE: {len(inner)} bytes ({len(inner)/1048576:.1f} MB)")
    assert inner[:2] == b"MZ", "Inner PE missing MZ header!"

    # Stage 2: Patch
    print("[*] Stage 2: Patching inner PE")
    patched = bytearray(inner)
    for p in PATCHES:
        foff = va_to_foff(p["va"])
        actual = bytes(patched[foff:foff + len(p["expected"])])
        assert actual == p["expected"], \
            f"{p['name']}: expected {p['expected'].hex()}, got {actual.hex()}"
        patched[foff:foff + len(p["patch"])] = p["patch"]
        print(f"    [{p['name']}] VA=0x{p['va']:x} foff=0x{foff:x}: "
              f"{p['expected'].hex(' ')} -> {p['patch'].hex(' ')}")
        print(f"      {p['desc']}")

    # Stage 3: Re-encode
    print("[*] Stage 3: Re-encoding (LZMA1 + XOR)")
    encrypted, new_payload_len = encode_inner(bytes(patched))

    # Stage 4: Build new outer PE
    print("[*] Stage 4: Building new outer PE")
    new_raw = bytearray(raw)

    # Check if new payload fits in .data section
    data_rawsize = 0x7e3c00  # .data raw size from PE header
    if new_payload_len > data_rawsize:
        print(f"    ERROR: new payload ({new_payload_len}) > .data rawsize ({data_rawsize})")
        return
    print(f"    payload: {new_payload_len} bytes (max {data_rawsize}, "
          f"original {ENC_LEN})")

    # Write encrypted payload into .data section
    new_raw[DATA_RAWPTR:DATA_RAWPTR + new_payload_len] = encrypted
    # Zero-fill remaining space
    remaining = data_rawsize - new_payload_len
    if remaining > 0:
        for i in range(remaining):
            new_raw[DATA_RAWPTR + new_payload_len + i] = 0

    # Update decrypt length in loader code if size changed
    if new_payload_len != ENC_LEN:
        # mov esi, imm32 at VA 0x4033ff (foff 0x37ff)
        # be 1a 3a 7e 00 -> be xx xx xx xx
        len_foff = 0x2800  # foff of imm32 in 'mov esi, imm32' at VA 0x4033ff
        struct.pack_into('<I', new_raw, len_foff, new_payload_len)
        print(f"    Updated decrypt length: 0x{ENC_LEN:x} -> 0x{new_payload_len:x}")
    else:
        print(f"    Decrypt length unchanged: 0x{new_payload_len:x}")

    # Write output
    print(f"[*] Writing {OUT}")
    with open(OUT, "wb") as f:
        f.write(new_raw)
    print(f"    {len(new_raw)} bytes written")

    # Verify
    print("[*] Verifying patched output")
    verify_inner = decode_outer(bytes(new_raw))
    assert verify_inner[:2] == b"MZ", "Verification failed: no MZ"
    for p in PATCHES:
        foff = va_to_foff(p["va"])
        actual = verify_inner[foff:foff + len(p["patch"])]
        assert actual == p["patch"], \
            f"Verify {p['name']}: got {actual.hex()}, expected {p['patch'].hex()}"
        print(f"    [{p['name']}] OK")

    print(f"\n[+] Done in {time.time()-t0:.1f}s")
    print(f"    Output: {OUT}")
    print(f"    Patches applied: {len(PATCHES)}")
    for p in PATCHES:
        print(f"      - {p['name']}: {p['desc']}")


if __name__ == "__main__":
    main()
