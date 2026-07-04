"""
AnyDesk v9.7.8 comprehensive patcher.
Removes:
  1. Disconnect countdown timer
  2. Free license / trial banner ads
  3. Premium feature dialogs (upgrade prompts)
  4. Address book entry limits
  5. Screen recording restrictions
  6. Session invitation restrictions

Pipeline:
  1. Decode outer AnyDesk.exe (XOR decrypt + LZMA1 decompress) -> inner PE
  2. Patch inner PE (8 byte-level patches)
  3. Re-encode (LZMA1 compress + XOR encrypt) -> new AnyDesk.exe
"""
import struct, lzma, time

SRC = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk.exe"
OUT = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_patched.exe"

MULT = 0x19660D
ADD  = 0x3C6EF35F
SEED = 0x55F4
DATA_RAWPTR = 0x3400
LZMA_PROPS = 0x5D
LZMA_DICT  = 0x04000000

def va_to_foff(va):
    return va - 0x10000000 - 0x1000 + 0x400

PATCHES = [
    # === Previously working patches ===
    {
        "name": "countdown_skip",
        "va": 0x10626bbb,
        "expected": b"\x83\xe8\x00",
        "patch": b"\x33\xc0\x90",
        "desc": "Skip disconnect countdown timer (always case_0)"
    },
    {
        "name": "banner_no_ui_add",
        "va": 0x106c376f,
        "expected": b"\xe8\xf0\xff\x6b\x00",
        "patch": b"\x90\x90\x90\x90\x90",
        "desc": "Prevent banner from being added to UI"
    },
    {
        "name": "banner_formatter_ret",
        "va": 0x1084e520,
        "expected": b"\x55\x8b\xec",
        "patch": b"\x33\xc0\xc2\x10\x00",
        "desc": "Banner formatter returns immediately"
    },
    # === New license unlock patches ===
    {
        "name": "premium_dialog_1_skip",
        "va": 0x10670788,
        "expected": b"\x74\x58",
        "patch": b"\xEB\x58",
        "desc": "Skip premium feature dialog #1 (je->jmp, always bypass)"
    },
    {
        "name": "abook_limit_bypass",
        "va": 0x108c2f4b,
        "expected": b"\x0f\x85\x6b\x01\x00\x00",
        "patch": b"\x90\xe9\x6b\x01\x00\x00",
        "desc": "Bypass address book entry count limit (jne->jmp)"
    },
    {
        "name": "screen_record_allow_1",
        "va": 0x105c3f19,
        "expected": b"\x0f\x85\xb0\x01\x00\x00",
        "patch": b"\x90\xe9\xb0\x01\x00\x00",
        "desc": "Allow screen recording check #1 (jne->jmp, always allow)"
    },
    {
        "name": "screen_record_allow_2",
        "va": 0x105c3f32,
        "expected": b"\x0f\x85\x8a\x00\x00\x00",
        "patch": b"\x90\xe9\x8a\x00\x00\x00",
        "desc": "Allow screen recording check #2 (jne->jmp, always allow)"
    },
    {
        "name": "session_invite_allow",
        "va": 0x10727b75,
        "expected": b"\x75\x07",
        "patch": b"\xEB\x07",
        "desc": "Allow session invitations on all licenses (jne->jmp)"
    },
]


def lcg_xor(data, seed=SEED):
    out = bytearray(data)
    s = seed
    for i in range(len(out)):
        s = (s * MULT + ADD) & 0xFFFFFFFF
        out[i] ^= (s >> 12) & 0xFF
    return bytes(out)


def decode_outer(raw):
    enc_len = struct.unpack_from('<I', raw, 0x2800)[0]
    enc = raw[DATA_RAWPTR:DATA_RAWPTR + enc_len]
    decrypted = lcg_xor(enc)
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                filters=[{"id": lzma.FILTER_LZMA1,
                                          "dict_size": LZMA_DICT,
                                          "lc": 3, "lp": 0, "pb": 2}])
    return dec.decompress(decrypted[5:])


def encode_inner(inner):
    comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW,
                               filters=[{"id": lzma.FILTER_LZMA1,
                                         "dict_size": LZMA_DICT,
                                         "lc": 3, "lp": 0, "pb": 2,
                                         "preset": 9 | lzma.PRESET_EXTREME}])
    compressed = comp.compress(inner) + comp.flush()
    header = bytes([LZMA_PROPS]) + struct.pack('<I', LZMA_DICT)
    payload = header + compressed
    print(f"  LZMA: {len(inner)} -> {len(payload)} bytes")
    return lcg_xor(payload), len(payload)


def main():
    t0 = time.time()
    print(f"[*] Reading {SRC}")
    raw = open(SRC, "rb").read()
    print(f"    outer PE: {len(raw)} bytes")

    print("[*] Stage 1: Decoding (XOR + LZMA1)")
    inner = decode_outer(raw)
    print(f"    inner PE: {len(inner)} bytes ({len(inner)/1048576:.1f} MB)")
    assert inner[:2] == b"MZ", "Inner PE missing MZ!"

    print(f"[*] Stage 2: Patching inner PE ({len(PATCHES)} patches)")
    patched = bytearray(inner)
    for p in PATCHES:
        foff = va_to_foff(p["va"])
        actual = bytes(patched[foff:foff + len(p["expected"])])
        assert actual == p["expected"], \
            f"{p['name']}: expected {p['expected'].hex()}, got {actual.hex()}"
        patched[foff:foff + len(p["patch"])] = p["patch"]
        print(f"    [{p['name']}] VA=0x{p['va']:x}: "
              f"{p['expected'].hex(' ')} -> {p['patch'].hex(' ')}")
        print(f"      {p['desc']}")

    print("[*] Stage 3: Re-encoding (LZMA1 + XOR)")
    encrypted, new_len = encode_inner(bytes(patched))

    print("[*] Stage 4: Building new outer PE")
    new_raw = bytearray(raw)
    data_rawsize = 0x7e3c00
    assert new_len <= data_rawsize, f"Payload too large: {new_len} > {data_rawsize}"
    print(f"    payload: {new_len} bytes (max {data_rawsize})")
    new_raw[DATA_RAWPTR:DATA_RAWPTR + new_len] = encrypted
    for i in range(data_rawsize - new_len):
        new_raw[DATA_RAWPTR + new_len + i] = 0
    if new_len != struct.unpack_from('<I', raw, 0x2800)[0]:
        struct.pack_into('<I', new_raw, 0x2800, new_len)
        print(f"    Updated decrypt length: 0x{new_len:x}")

    print(f"[*] Writing {OUT}")
    with open(OUT, "wb") as f:
        f.write(new_raw)
    print(f"    {len(new_raw)} bytes written")

    print("[*] Verifying patched output")
    verify = decode_outer(bytes(new_raw))
    assert verify[:2] == b"MZ", "Verification failed: no MZ"
    for p in PATCHES:
        foff = va_to_foff(p["va"])
        actual = verify[foff:foff + len(p["patch"])]
        assert actual == p["patch"], f"Verify {p['name']}: mismatch"
        print(f"    [{p['name']}] OK")

    print(f"\n[+] Done in {time.time()-t0:.1f}s")
    print(f"    Output: {OUT}")
    print(f"    Patches: {len(PATCHES)}")
    for p in PATCHES:
        print(f"      - {p['name']}: {p['desc']}")


if __name__ == "__main__":
    main()
