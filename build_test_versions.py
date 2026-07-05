"""
Build 5 test versions, each with countdown_skip + one additional patch.
User tests all 5 to identify which patch causes the crash.
"""
import struct, lzma, time, os

SRC = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk.exe"
OUT_DIR = "/Users/macdev/Demo/Tools/AnyDesk"

MULT = 0x19660D; ADD = 0x3C6EF35F; SEED = 0x55F4
DATA_RAWPTR = 0x3400; LZMA_PROPS = 0x5D; LZMA_DICT = 0x04000000

def va_to_foff(va): return va - 0x10000000 - 0x1000 + 0x400

def lcg_xor(data, seed=SEED):
    out = bytearray(data); s = seed
    for i in range(len(out)):
        s = (s * MULT + ADD) & 0xFFFFFFFF
        out[i] ^= (s >> 12) & 0xFF
    return bytes(out)

def decode_outer(raw):
    enc_len = struct.unpack_from('<I', raw, 0x2800)[0]
    enc = raw[DATA_RAWPTR:DATA_RAWPTR + enc_len]
    decrypted = lcg_xor(enc)
    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                filters=[{"id": lzma.FILTER_LZMA1, "dict_size": LZMA_DICT, "lc": 3, "lp": 0, "pb": 2}])
    return dec.decompress(decrypted[5:])

def encode_inner(inner):
    comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW,
                               filters=[{"id": lzma.FILTER_LZMA1, "dict_size": LZMA_DICT, "lc": 3, "lp": 0, "pb": 2,
                                         "preset": 9 | lzma.PRESET_EXTREME}])
    compressed = comp.compress(inner) + comp.flush()
    payload = bytes([LZMA_PROPS]) + struct.pack('<I', LZMA_DICT) + compressed
    return lcg_xor(payload), len(payload)

countdown = {"name": "countdown_skip", "va": 0x10626bbb, "expected": b"\x83\xe8\x00", "patch": b"\x33\xc0\x90"}

extra_patches = [
    ("banner", {"name": "banner_no_ui_add", "va": 0x106c376f, "expected": b"\xe8\xf0\xff\x6b\x00", "patch": b"\x90\x90\x90\x90\x90"}),
    ("premium", {"name": "premium_dialog_1_skip", "va": 0x10670788, "expected": b"\x74\x58", "patch": b"\xEB\x58"}),
    ("record", {"name": "screen_record_allow", "va": 0x105c3f19, "expected": b"\x0f\x85\xb0\x01\x00\x00", "patch": b"\x90\xe9\xb0\x01\x00\x00"}),
    ("abook", {"name": "abook_limit_bypass", "va": 0x108c2f4b, "expected": b"\x0f\x85\x6b\x01\x00\x00", "patch": b"\x90\xe9\x6b\x01\x00\x00"}),
    ("invite", {"name": "session_invite_allow", "va": 0x10727b75, "expected": b"\x75\x07", "patch": b"\xEB\x07"}),
]

raw = open(SRC, "rb").read()
inner_orig = decode_outer(raw)

for label, extra in extra_patches:
    patches = [countdown, extra]
    patched = bytearray(inner_orig)
    for p in patches:
        foff = va_to_foff(p["va"])
        actual = bytes(patched[foff:foff + len(p["expected"])])
        assert actual == p["expected"], f"{p['name']}: {actual.hex()} != {p['expected'].hex()}"
        patched[foff:foff + len(p["patch"])] = p["patch"]

    encrypted, new_len = encode_inner(bytes(patched))
    new_raw = bytearray(raw)
    new_raw[DATA_RAWPTR:DATA_RAWPTR + new_len] = encrypted
    for i in range(0x7e3c00 - new_len):
        new_raw[DATA_RAWPTR + new_len + i] = 0
    struct.pack_into('<I', new_raw, 0x2800, new_len)

    out_path = os.path.join(OUT_DIR, f"AnyDesk_test_{label}.exe")
    with open(out_path, "wb") as f:
        f.write(new_raw)

    # Verify
    verify = decode_outer(bytes(new_raw))
    ok = True
    for p in patches:
        foff = va_to_foff(p["va"])
        if verify[foff:foff + len(p["patch"])] != p["patch"]:
            ok = False
    status = "OK" if ok else "FAIL"
    print(f"[{status}] {label}: {out_path} ({len(patches)} patches, {new_len} bytes)")

print("\nDone. Test each file on Windows:")
for label, _ in extra_patches:
    print(f"  AnyDesk_test_{label}.exe")
