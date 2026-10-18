#!/usr/bin/env python3
"""Fake IBM i server mapper for exercising ibmi-svrmap-info.nse locally.

Follows my memory of the exchange (name in, '+' and a 4-byte port out). That
proves the script and this mock agree, NOT that a real IBM i behaves this way.

Usage: mock-svrmap.py [port]      (default 2449, no root needed)
"""
import socket, struct, sys

PORTS = {
    b"as-central": 8470, b"as-central-s": 9470,
    b"as-database": 8471, b"as-database-s": 9471,
    b"as-dtaq": 8472,                              # no TLS twin on purpose
    b"as-file": 8473, b"as-file-s": 9473,
    b"as-netprt": 8474, b"as-netprt-s": 9474,
    b"as-rmtcmd": 8475,                            # no TLS twin on purpose
    b"as-signon": 8476, b"as-signon-s": 19476,     # moved off default on purpose
}

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 2449))
srv.listen(5)
print("mock svrmap listening")
while True:
    conn, _ = srv.accept()
    try:
        conn.settimeout(2)
        name = conn.recv(64)
        if name in PORTS:
            conn.sendall(b"\x2b" + struct.pack(">I", PORTS[name]))
        else:
            conn.sendall(b"\x2d")
    except OSError:
        pass
    conn.close()
