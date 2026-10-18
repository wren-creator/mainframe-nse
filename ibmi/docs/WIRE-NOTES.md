# Wire notes: what the scripts send, what came back

Working notes for the `ibmi/` scripts. Every layout below is tagged one of
three ways, so nobody has to guess how much to trust it:

- **Confirmed**: seen on a live IBM i (PUB400, IBM i 7.5, 2026-10-18).
- **Assumed**: written from memory of the protocol, not yet seen on a real
  system. Treat as a draft.
- **Not seen**: handled by the parser but never met in a real capture.

## 1. TN5250 on 23 and 992 (`tn5250-info`)

References: RFC 1205 (5250 over telnet), RFC 4777 (IBM's NEW-ENVIRON
extensions).

### Telnet negotiation

Confirmed. PUB400 opens the conversation, in this order:

```
DO NEW-ENVIRON
DO TERMINAL-TYPE
DO END-OF-RECORD
WILL END-OF-RECORD
DO BINARY
WILL BINARY
```

We answer WILL to every DO we support, DO to every WILL, and refuse the rest.
Respond-only was enough. The server did not need us to speak first, and no 5250
Query structured field had to be answered before the sign-on screen arrived.

Our answers:

- TERMINAL-TYPE: `IBM-3179-2` (24x80 color display). Wide screens use
  `IBM-3477-FC` and a 27x132 grid.
- NEW-ENVIRON: `KBDTYPE=USB`, `CODEPAGE=37`, `CHARSET=697`, and nothing else
  unless `tn5250-info.devname` is set. Never `USER`, `IBMRSEED` or
  `IBMSUBSPW`, which are the auto-sign-on variables.

### Device name

By default we send no `DEVNAME`. The server hands out an ordinary `QPADEVxxxx`
virtual device (PUB400 gave `QPADEV0067` on 23, `QPADEV0006` on 992), and
nothing new is created. A custom name can make an IBM i with auto-create on
build a new device description, which is litter on a client's system, so it is
opt-in only.

### Record framing

Confirmed. One screen arrived as one telnet record ending in `IAC EOR`:

```
032d            total length, 813, counts these two bytes
12a0            GDS record type
0000            reserved
04 0000 03      variable header: length 4, flags, opcode 0x03
```

Data starts at byte 11. The record held:

| Bytes | Meaning | Status |
|---|---|---|
| `04 40` | ESC Clear Unit | Confirmed |
| `04 11 00 18` | ESC Write To Display, control bytes CC1 CC2 | Confirmed |
| `01 07` + 7 bytes | SOH, the length does not count itself | Confirmed |
| `11 row col` | SBA, set buffer address, 1 based | Confirmed |
| `20`-`3F` alone | display attribute, takes one screen position | Confirmed |
| `1D` FFW attr len | SF, start field | Confirmed |
| `02 row col char` | RA, repeat to address (PUB400 fills with `00`) | Confirmed, end point inclusive is a guess |
| `04 52 00 00` | ESC Read MDT Fields, ends the record | Confirmed |
| `03` EA, `10` TD, `15` WDSF, `12` WEA, `14` MC | | Not seen |

Read MDT Fields at the end means the keyboard is open and the server is
waiting for input. We never answer it.

### Screen grid

The grid has to match the terminal. PUB400 writes past column 80 and relies
on the wrap, so a 132 column grid mangled the layout. Rule: 24x80 for
`IBM-3179-2`, 27x132 for the 3477 and 3180 families.

### What a sign-on screen gives away

Confirmed on PUB400, with its customized labels:

```
Server name . . . :   PUB400          (stock IBM i says "System")
Subsystem . . . . :   QINTER
Display name. . . :   QPADEV0067      (stock says "Display")
Your user name:                       (stock says "User")
Password (max. 128):
```

Sites rename these, so the parser accepts both wordings. Two things to
remember when reading the output:

- The **release** (`releaseHintFromBanner: 7.5`) comes from the site's own
  greeting ("Welcome to IBM i 7.5"). It is a hint, not a measurement.
- The **copyright year** is not a release indicator. PUB400 shows
  "1980, 2021" on a 7.5 system.

### The two ports landed in different subsystems

Plain 23 gave `QINTER`, TLS 992 gave `QINTER2`, same host. Worth a look on a
real engagement, since it can mean separate job and security setups per
entry point.

### TLS on 992

Nmap's own `ssl-cert` and `ssl-enum-ciphers` cover this, and the 5250 session
inside TLS behaved exactly like the plain one. PUB400, for reference:
ECDSA P-256 certificate from a public CA, TLS 1.2 and 1.3 only, AEAD ciphers
only, rated A.

## 2. Server mapper on 449 (`ibmi-svrmap-info`)

All **confirmed**, 14 of 14 lookups on PUB400.

```
request   ASCII service name, no terminator, one connection per name
reply     2B  then a 4 byte big-endian port
```

Service names: `as-central`, `as-database`, `as-dtaq`, `as-file`,
`as-netprt`, `as-rmtcmd`, `as-signon`, each with an `-s` twin for TLS.

Results: plain 8470 to 8476 and TLS 9470 to 9476, all at the documented
defaults. Example: `as-central` plain replied `2b 00 00 21 16` (8470), TLS
replied `2b 00 00 24 fe` (9470).

Not seen: what the mapper sends for a name it does not know, and whether it
allows more than one lookup on a single connection. The script does not
depend on either.

## 3. Sign-on server on 8476 and 9476 (`ibmi-signon-info`)

All **assumed**. Not yet run against a real system.

```
request   20 byte header: length(4) 0000 E009 00000000 00000000 0000 7003
          then three LLCPs (length(4) code point(2) data):
            1101 client version      00000001
            1102 datastream level    0002
            1103 client seed         8 random bytes
reply     same 20 byte header with request id F004, a template that starts
          with a 4 byte return code, then LLCPs:
            1101 server version      4 bytes, (version<<16)|(release<<8)|mod
            1102 datastream level    2 bytes
            1103 server seed         8 bytes, never printed
            1114 CCSID               4 bytes
            1119 password level      1 byte, the QPWDLVL value
```

Password level meaning: 0 and 1 give 10 character passwords with DES-era
storage, 2 and 3 allow passphrases up to 128 characters. Levels above 3 print
as a raw number until their meaning is checked.

If the first live run fails, the script prints the raw reply with the error.
Send that and the layout above gets fixed from real bytes.

## 4. Test fixtures and mocks

Mocks are in `test/`, each written from the same reading of the protocol as
the script it feeds. They prove the two agree, nothing more. The real
evidence is the capture in `test/fixtures/`. See `test/README.md`.

## 5. What a hosted system hides

A shared hosted box can filter ports or customize screens in ways a client's
own system will not. PUB400 is a good first reference, not the whole picture.
A stock sign-on screen and a system with restricted ports are still wanted
test cases.
