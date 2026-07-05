"""Full round-trip integrity check: decode patched output, compare every byte with expected."""
import struct, lzma

SRC = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk.exe"
OUT = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_patched.exe"
INNER = "/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_inner.exe"

MULT = 0x19660D; ADD = 0x3C6EF35F; SEED = 0x55F4
DATA_RAWPTR = 0x3400; LZMA_PROPS = 0x5D; LZMA_DICT = 0x04000000

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
                                filters=[{"id": lzma.FILTER_LZMA1,
                                          "dict_size": LZMA_DICT,
                                          "lc": 3, "lp": 0, "pb": 2}])
    return dec.decompress(decrypted[5:])

# Load original inner PE
inner_orig = open(INNER, "rb").read()
print(f"Original inner PE: {len(inner_orig)} bytes")

# Load patched output and decode
patched_raw = open(OUT, "rb").read()
inner_patched = decode_outer(patched_raw)
print(f"Patched inner PE:  {len(inner_patched)} bytes")

if len(inner_orig) != len(inner_patched):
    print(f"LENGTH MISMATCH: {len(inner_orig)} vs {len(inner_patched)}")

# Compare byte by byte
diffs = []
for i in range(min(len(inner_orig), len(inner_patched))):
    if inner_orig[i] != inner_patched[i]:
        diffs.append((i, inner_orig[i], inner_patched[i]))

print(f"\nTotal byte differences: {len(diffs)}")
for foff, orig, patched in diffs:
    va = 0x10000000 + 0x1000 + (foff - 0x400) if foff >= 0x400 else 0
    print(f"  foff=0x{foff:x} VA=0x{va:08x}: {orig:02x} -> {patched:02x}")

# Also check: decode the ORIGINAL AnyDesk.exe and compare with inner PE
print("\n=== Verifying original round-trip ===")
orig_raw = open(SRC, "rb").read()
inner_from_orig = decode_outer(orig_raw)
print(f"Decoded from original: {len(inner_from_orig)} bytes")
orig_diffs = sum(1 for i in range(min(len(inner_orig), len(inner_from_orig))) if inner_orig[i] != inner_from_orig[i])
print(f"Differences from original: {orig_diffs}")
