#!/usr/bin/env python3
"""Serve the captured host server fixture so a script can be tested against
real bytes instead of a mock's reading of them.

Usage: replay-hostserver.py [fixture.json] [mapper_port] [signon_port]
       defaults: test/fixtures/pub400-hostserver.json, 4449, 8476

The mapper answers each service name with the bytes the live server sent, so
its ports come back as 8470 to 8476 and 9470 to 9476. The sign-on server
answers an exchange-attributes request with the captured reply. Anything else
gets the connection dropped. Plain only, no TLS.
"""
import json, socket, sys, threading, os

here = os.path.dirname(os.path.abspath(__file__))
fx = json.load(open(sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "fixtures", "pub400-hostserver.json")))
mapper_port = int(sys.argv[2]) if len(sys.argv) > 2 else 4449
signon_port = int(sys.argv[3]) if len(sys.argv) > 3 else 8476
mapper = {k: bytes.fromhex(v) for k, v in fx["mapper"].items()}
reply = bytes.fromhex(fx["signon_reply"])

def serve(port, handler):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(8)
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(2); handler(c)
        except OSError:
            pass
        c.close()

def map_handler(c):
    name = c.recv(64).decode("ascii", "replace").strip()
    c.sendall(mapper.get(name, b"\x2d"))

def signon_handler(c):
    req = c.recv(512)
    if len(req) >= 20 and req[6:8] == b"\xe0\x09" and req[18:20] == b"\x70\x03":
        c.sendall(reply)

threading.Thread(target=serve, args=(signon_port, signon_handler), daemon=True).start()
print("replaying", fx["source"], "| mapper", mapper_port, "| sign-on", signon_port, flush=True)
serve(mapper_port, map_handler)
