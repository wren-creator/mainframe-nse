#!/usr/bin/env python3
"""Tiny fake IBM i telnet server for exercising tn5250-info.nse locally.

It follows the RFC 4777 flow as *I* understand it, so it proves the script
and this mock agree with each other. It does NOT prove either one matches a
real IBM i. Check against PUB400 or a capture for that.

Usage: mock-tn5250.py [port] [record.hex]
       default port 2323 (no root needed). With a hex file, the mock replays that
       captured 5250 record instead of the synthetic sign-on screen, e.g.
       test/fixtures/pub400-23-signon-record.hex
"""
import socket, sys

IAC, DONT, DO, WONT, WILL, SB, SE, EOR = 255, 254, 253, 252, 251, 250, 240, 239
TTYPE, BINARY, EOR_OPT, NEWENV = 24, 0, 25, 39

def e(s):
    return s.encode("cp037")

def sba(r, c):
    return bytes([0x11, r, c])

def record(data):
    # GDS header: len(2) 12A0 reserved(2) varhdr-len(1)=4 flags(2)... opcode
    body = bytes([0x12, 0xA0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x03]) + data
    total = len(body) + 2
    return bytes([total >> 8, total & 0xFF]) + body

def signon_screen(system, subsystem, display):
    d = bytes([0x04, 0x40])                       # clear unit
    d += bytes([0x04, 0x11, 0x00, 0x00])          # write to display, CC1 CC2
    d += bytes([0x01, 0x03, 0x00, 0x00, 0x00])    # SOH, len 3 (assumed layout)
    d += sba(1, 70) + e("Sign On")
    d += sba(2, 54) + e("System  . . . . . :   " + system)
    d += sba(3, 54) + e("Subsystem  . . . . :   " + subsystem)
    d += sba(4, 54) + e("Display . . . . . :   " + display)
    d += sba(6, 17) + e("User  . . . . . . . . . . . . . .")
    d += sba(6, 53) + bytes([0x1D, 0x40, 0x00, 0x24, 0x00, 0x0A])  # SF: FFW attr len
    d += sba(7, 17) + e("Password  . . . . . . . . . . . .")
    d += sba(7, 53) + bytes([0x1D, 0x40, 0x00, 0x27, 0x00, 0x0A])
    d += sba(23, 3) + e("(C) COPYRIGHT IBM CORP. 1980, 2024.")
    return record(d)

def read_until(conn, needle, limit=2000):
    buf = b""
    conn.settimeout(3)
    try:
        while needle not in buf and len(buf) < limit:
            chunk = conn.recv(256)
            if not chunk:
                break
            buf += chunk
    except socket.timeout:
        pass
    return buf

def handle(conn):
    conn.sendall(bytes([IAC, DO, TTYPE]))
    conn.sendall(bytes([IAC, DO, EOR_OPT, IAC, WILL, EOR_OPT, IAC, DO, BINARY, IAC, WILL, BINARY]))
    got = read_until(conn, bytes([IAC, WILL, TTYPE]))
    conn.sendall(bytes([IAC, SB, TTYPE, 1, IAC, SE]))
    got += read_until(conn, b"IBM-")
    conn.sendall(bytes([IAC, DO, NEWENV]))
    got += read_until(conn, bytes([IAC, WILL, NEWENV]))
    conn.sendall(bytes([IAC, SB, NEWENV, 1, IAC, SE]))
    got += read_until(conn, bytes([IAC, SE]))
    print("client said:", got.hex())
    if len(sys.argv) > 2:
        scr = bytes.fromhex(open(sys.argv[2]).read().strip())
    else:
        scr = signon_screen("MOCKI1", "QINTER", "QPADEV0003")
    conn.sendall(scr.replace(b"\xff", b"\xff\xff") + bytes([IAC, EOR]))
    try:
        conn.settimeout(2)
        conn.recv(256)
    except Exception:
        pass
    conn.close()

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2323
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    print("mock tn5250 on", port)
    while True:
        conn, _ = srv.accept()
        try:
            handle(conn)
        except OSError as exc:
            # nmap's own port probe connects and hangs up; ignore it
            print("connection dropped:", exc)
            conn.close()

main()
