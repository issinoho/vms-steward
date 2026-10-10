"""fcgi_client.py - a minimal FastCGI client, enough to talk to steward.

Used by tests/api/test_api.py and tools/devserver.py. Standard library only.
"""
import socket
import struct

BEGIN_REQUEST, END_REQUEST, PARAMS, STDIN, STDOUT, STDERR = 1, 3, 4, 5, 6, 7


def _pair_len(n):
    return bytes([n]) if n < 128 else struct.pack(">I", n | 0x80000000)


def _pairs(params):
    out = b""
    for k, v in params.items():
        k, v = k.encode("latin-1"), v.encode("latin-1")
        out += _pair_len(len(k)) + _pair_len(len(v)) + k + v
    return out


def _record(rtype, rid, content):
    out = b""
    for i in range(0, max(len(content), 1), 65535):
        chunk = content[i:i + 65535]
        out += struct.pack(">BBHHBx", 1, rtype, rid, len(chunk), 0) + chunk
    return out


def request(addr, params, body=b"", rid=1, timeout=10):
    """Send one request; return (status, headers as list of (name, value), body)."""
    s = socket.create_connection(addr, timeout=timeout)
    try:
        msg = _record(BEGIN_REQUEST, rid, struct.pack(">HB5x", 1, 0))
        msg += _record(PARAMS, rid, _pairs(params)) + _record(PARAMS, rid, b"")
        if body:
            msg += _record(STDIN, rid, body)
        msg += _record(STDIN, rid, b"")
        s.sendall(msg)
        buf, out = b"", b""
        while True:
            data = s.recv(65536)
            if not data:
                break
            buf += data
            ended = False
            while len(buf) >= 8:
                _, rtype, _, clen, plen = struct.unpack(">BBHHBx", buf[:8])
                if len(buf) < 8 + clen + plen:
                    break
                content = buf[8:8 + clen]
                buf = buf[8 + clen + plen:]
                if rtype == STDOUT:
                    out += content
                elif rtype == END_REQUEST:
                    ended = True
            if ended:
                break
    finally:
        s.close()
    head, _, payload = out.partition(b"\r\n\r\n")
    status, headers = 200, []
    for line in head.decode("latin-1").split("\r\n"):
        name, _, value = line.partition(": ")
        if name.lower() == "status":
            status = int(value.split()[0])
        else:
            headers.append((name, value))
    return status, headers, payload
