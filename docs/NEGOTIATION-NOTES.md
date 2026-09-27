# TN3270E negotiation reference

Notes used while writing `lib/tn3270.lua`. Cross-checked against the working
implementation in `web3270`'s `Bridge_server/tn3270/session.js` (which
negotiates the other side of this same exchange — client role there, we're
implementing the client role here too, since Nmap connects out like any
other TN3270E client would).

Protocol references:
- RFC 1576 — TN3270
- RFC 1647 — TN3270 Enhancements (superseded by RFC 2355)
- RFC 2355 — TN3270E
- IBM GA23-0059 — 3270 Data Stream Programmer's Reference

## Telnet command bytes

| byte | name |
|------|------|
| 0xFF | IAC  |
| 0xFE | DONT |
| 0xFD | DO   |
| 0xFC | WONT |
| 0xFB | WILL |
| 0xFA | SB (start subnegotiation) |
| 0xF0 | SE (end subnegotiation) |
| 0xEF | EOR (end of record — marks the end of a 3270 data record) |
| 0xF1 | NOP |

## Telnet options relevant here

| byte | option |
|------|--------|
| 0x00 | BINARY |
| 0x18 | TERMINAL-TYPE (TTYPE) |
| 0x19 | END-OF-RECORD (EOR) |
| 0x28 | TN3270E |

## TN3270E sub-option function codes (the byte right after `IAC SB 0x28`)

| byte | name |
|------|------|
| 0x00 | ASSOCIATE |
| 0x01 | CONNECT |
| 0x02 | DEVICE-TYPE |
| 0x03 | FUNCTIONS |
| 0x04 | IS |
| 0x05 | REASON |
| 0x06 | REJECT |
| 0x07 | REQUEST |
| 0x08 | SEND |

`IS`/`REQUEST`/`REJECT`/`SEND` double as the second-level qualifier under
`DEVICE-TYPE` or `FUNCTIONS`, e.g. `DEVICE-TYPE REQUEST` vs. `DEVICE-TYPE IS`.

## FUNCTIONS capability codes (a separate byte-value space, used only inside
a FUNCTIONS REQUEST/IS payload list)

| byte | capability |
|------|------------|
| 0x00 | BIND-IMAGE |
| 0x01 | DATA-STREAM-CTL |
| 0x02 | RESPONSES (requires sending RESPONSE data-type records back — not implemented here, never request this) |
| 0x03 | SCS-CTL-CODES |
| 0x04 | SYSREQ |

## The actual handshake, as a client connecting out

1. Server sends `IAC DO TN3270E`.
2. Client replies `IAC WILL TN3270E`.
3. Server sends `IAC SB TN3270E SEND DEVICE-TYPE IAC SE`.
4. Client replies `IAC SB TN3270E DEVICE-TYPE REQUEST IBM-<model> [CONNECT
   <lu-name>] IAC SE` — model is something like `3278-2` or `3279-2-E`; the
   LU name (CONNECT) is only sent if the client wants a specific LU.
5. Server replies either:
   - `IAC SB TN3270E DEVICE-TYPE IS <device> [CONNECT LU=<lu>] IAC SE`
     (accepted — note the granted LU may differ from what was requested,
     that's the LU-fixation angle `web3270` already tracks), or
   - `IAC SB TN3270E DEVICE-TYPE REJECT REASON <code> IAC SE` — reason codes:
     `0x00 CONN-PARTNER`, `0x01 DEVICE-IN-USE`, `0x02 INV-ASSOCIATE`,
     `0x03 INV-NAME`, `0x04 INV-DEVICE-TYPE`, `0x05 TYPE-NAME-ERROR`,
     `0x06 UNKNOWN-ERROR`, `0x07 UNSUPPORTED-REQ`.
6. Client and server exchange `FUNCTIONS REQUEST`/`FUNCTIONS IS` the same
   way, negotiating which capability codes both sides support.
7. Normal 3270 data records follow, each terminated by `IAC EOR`. **v1 of
   this repo stops here** — it reads the first data record's raw bytes just
   far enough to strip 3270 orders and extract displayable text for banner
   matching, but does not build a full screen/field model. That's out of
   scope for the negotiation-only script (see `FEASIBILITY.md`).

## Minimal order-aware text extraction (v1 scope)

To pull banner text out of the first screen without a full field model, the
byte stream just needs enough order-awareness to skip over each order's
parameter bytes so they don't get mistaken for displayable EBCDIC text:

| order | byte | parameter bytes to skip |
|-------|------|--------------------------|
| Start Field (SF)          | 0x1D | 1 (attribute byte) |
| Start Field Extended (SFE)| 0x29 | `1 + 2*count` (count byte, then count pairs) |
| Set Buffer Address (SBA)  | 0x11 | 2 (buffer address) |
| Set Attribute (SA)        | 0x28 | 2 (attribute type + value) |
| Modify Field (MF)         | 0x2C | `1 + 2*count` |
| Insert Cursor (IC)        | 0x13 | 0 |
| Program Tab (PT)          | 0x05 | 0 |
| Repeat to Address (RA)    | 0x3C | 3 (buffer address x2 + char to repeat) |
| Erase Unprotected (EUA)   | 0x12 | 2 (buffer address) |

Everything else is treated as an EBCDIC (CP037) text byte and translated for
matching. This is deliberately a subset of what
`Bridge_server/tn3270/session.js` does — enough to read plain text off a
logon/error screen, not a full renderer.
