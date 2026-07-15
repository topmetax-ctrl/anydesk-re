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

rdata_start = sections[1][4] if len(sections) > 1 else 0
rdata_end = rdata_start + sections[1][3] if len(sections) > 1 else 0

# Search for session-related strings
search_terms = [
    b'session_limit',
    b'session.max',
    b'session.timeout',
    b'session.duration',
    b'session.expired',
    b'session_time',
    b'max_session',
    b'session_count',
    b'session.count',
    b'limit.session',
    b'free.session',
    b'session.free',
    b'session_end',
    b'session.end',
    b'session_disconnect',
    b'session.disconnect',
    b'retry',
    b'retry_limit',
    b'retry.count',
    b'retry_count',
    b'max_retry',
    b'max.connect',
    b'max_session',
    b'session_reconnect',
    b'time_limit',
    b'timeout',
    b'disconnect',
    b'closed',
    b'closed.socket',
    b'closed.retry',
    b'reconnect',
    b'queue',
    b'queue.full',
    b'queue_limit',
    b'conn_limit',
    b'connection_limit',
    b'max_conn',
    b'max_connection',
    b'lic.',
    b'license.',
    b'lic.free',
    b'free_lic',
    b'free.lic',
]

print("=== Session/limit related strings ===")
for term in search_terms:
    pos = 0
    while True:
        pos = b.find(term, pos)
        if pos < 0:
            break
        # Get full string (null-terminated)
        end = b.find(b'\x00', pos, pos + 200)
        if end < 0:
            end = pos + len(term)
        full = b[pos:end].decode('latin1', 'replace')
        va = foff_to_va(pos)
        # Only show if in .rdata or .text
        print("  0x%08x: '%s'" % (va, full))
        pos += 1
