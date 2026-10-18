#!/usr/bin/env python3
"""Fake IBM i sign-on server for exercising ibmi-signon-info.nse locally.

Shaped after a live capture from PUB400 (IBM i 7.5): reply id F003, code
points 1101, 1102, 1103, 1119 and 111F.

Usage: mock-signon.py [port] [pwdlevel]   (defaults 2476, 2)
"""
import socket, struct, sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 2476
pwdlvl = int(sys.argv[2]) if len(sys.argv) > 2 else 2

def llcp(cp, data):
    return struct.pack(">IH", len(data) + 6, cp) + data

body = (llcp(0x1101, struct.pack(">I", (7 << 16) | (5 << 8) | 0)) +
        llcp(0x1102, struct.pack(">H", 15)) +
        llcp(0x1103, b"\x01\x02\x03\x04\x05\x06\x07\x08") +
        llcp(0x1119, bytes([pwdlvl])) +
        llcp(0x111F, b"\x00\x00\x00\x00" + "135258/QUSER/QZSOSIGN".encode("cp037")))
template = struct.pack(">I", 0)  # return code 0
reply = struct.pack(">IHHIIHH", 20 + len(template) + len(body), 0, 0xE009, 0, 0,
                    len(template), 0xF003) + template + body

srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(5)
print("mock signon listening")
while True:
    conn, _ = srv.accept()
    try:
        conn.settimeout(2)
        req = conn.recv(512)
        print("request:", req.hex())
        conn.sendall(reply)
    except OSError:
        pass
    conn.close()
