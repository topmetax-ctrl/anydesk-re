import lzma, struct, re, time
t0=time.time()
data=open("/Users/macdev/Demo/Tools/AnyDesk/AnyDesk.exe","rb").read()
RAW=0x3400; N=0x7e3a1a
enc=data[RAW:RAW+N]
MULT=0x19660D; ADD=0x3C6EF35F

# Stage 1: LCG XOR decrypt
buf=bytearray(enc)
s=0x55F4
for i in range(N):
    s=(s*MULT+ADD)&0xFFFFFFFF
    buf[i]^=(s>>12)&0xFF
print("[1] XOR decrypt: %d bytes in %.1fs"%(len(buf),time.time()-t0))

# Stage 2: LZMA1 decompress (5-byte header: props + dict_size, no size field)
props=buf[0]; dictsize=struct.unpack_from('<I',buf,1)[0]
print("[2] LZMA1 props=0x%02x dictsize=0x%x"%(props,dictsize))
dec=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[{"id":lzma.FILTER_LZMA1,"dict_size":dictsize,"lc":3,"lp":0,"pb":2}])
out=dec.decompress(bytes(buf[5:]))
print("[2] LZMA1 decompress: %d bytes (%.1f MB) in %.1fs"%(len(out),len(out)/1048576,time.time()-t0))
print("    first 16: %s"%out[:16].hex(' '))

# Stage 3: verify PE
assert out[:2]==b'MZ', "no MZ!"
e=struct.unpack_from('<I',out,0x3C)[0]
assert out[e:e+4]==b'PE\x00\x00', "no PE sig!"
machine=struct.unpack_from('<H',out,e+4)[0]
nsec=struct.unpack_from('<H',out,e+6)[0]
opt=e+20
magic=struct.unpack_from('<H',out,opt)[0]
ep=struct.unpack_from('<I',out,opt+16)[0]
imgbase=struct.unpack_from('<I',out,opt+28)[0]
subsys=struct.unpack_from('<H',out,opt+68)[0]
print("[3] Inner PE: %s machine=0x%04x sections=%d entry=0x%x imgbase=0x%x subsys=%d"%(
    'PE32+' if magic==0x20b else 'PE32', machine, nsec, ep, imgbase, subsys))

# sections
sec_off=opt+struct.unpack_from('<H',out,e+16)[0]
print("[3] Sections:")
for i in range(nsec):
    s=sec_off+i*40
    nm=out[s:s+8].rstrip(b'\x00').decode('latin1')
    vs,va,rs,rp=struct.unpack_from('<IIII',out,s+8)
    print("    %-8s vsize=0x%-8x vaddr=0x%-8x rawsize=0x%-8x rawptr=0x%x"%(nm,vs,va,rs,rp))

# version info / strings
strs=re.findall(rb'[\x20-\x7e]{8,}',out[:0x100000])
print("[4] Sample strings (first 30):")
for s in strs[:30]:
    print("    ",s.decode('latin1'))

# look for AnyDesk version / pdb
for needle in [b'AnyDesk',b'.pdb',b'Gitlab-Runner',b'FileVersion',b'ProductName',b'OriginalFilename',b'InternalName',b'CompanyName',b'LegalCopyright']:
    idx=out.find(needle)
    print("    %-18r %s"%(needle, hex(idx) if idx>=0 else "not found"))

open("/Users/macdev/Demo/Tools/AnyDesk/AnyDesk_inner.exe","wb").write(out)
print("[+] wrote AnyDesk_inner.exe (%d bytes)"%len(out))
